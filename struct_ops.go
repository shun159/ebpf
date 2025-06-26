package ebpf

import (
	"debug/elf"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
)

const structOpsValuePrefix = "bpf_struct_ops_"
const structOpsLinkSec = ".struct_ops.link"
const structOpsSec = ".struct_ops"

// structOpsKernTypes holds information about kernel types related to struct_ops
type structOpsKernTypes struct {
	spec *btf.Spec
	// The target kernel struct type
	typ *btf.Struct
	// The BTF type ID of the target kernel struct
	typeID btf.TypeID
	// The wrapper struct type that contains the target struct
	valueType *btf.Struct
	// The BTF type ID of the wrapper struct
	valueTypeID btf.TypeID
	// The member within ValueType that holds the target struct
	dataMember *btf.Member
	// mod_btf
	modBtf uint32
}

type structOpsSpec struct {
	programSpecs []*ProgramSpec
	kernFuncOff  []uint32
	/* e.g. struct tcp_congestion_ops in bpf_prog's btf format */
	data []byte
	/* e.g. struct bpf_struct_ops_tcp_congestion_ops in
	 *      btf_vmlinux's format.
	 * struct bpf_struct_ops_tcp_congestion_ops {
	 *	[... some other kernel fields ...]
	 *	struct tcp_congestion_ops data;
	 * }
	 * kern_vdata-size == sizeof(struct bpf_struct_ops_tcp_congestion_ops)
	 * bpf_map__init_kern_struct_ops() will populate the "kern_vdata"
	 * from "data".
	 */
	kernVData []byte
	typeId    btf.TypeID
	btf       *btf.Spec
}

// structOpsMeta is a placeholder object inserted into MapSpec.Contents
// so that later stages (loader, ELF parser) can recognise this map as
// a struct‑ops map without adding public fields yet.
type structOpsMeta struct {
	name                  string
	typeID                btf.TypeID
	secIdx                elf.SectionIndex // section index of .struct_ops / .struct_ops.link
	varOffset             uint64           // byte offset of the variable in that section
	userSize              uint64           // sizeof(user struct) for range check
	progIdxMap            map[string]int
	attachBtfID           []btf.TypeID
	attachType            []sys.AttachType
	btfVmlinuxValueTypeId btf.TypeID
	// sturct_ops spec
	structOpsSpec *structOpsSpec
	// each user space map definition can use different BTF
	btf            *btf.Spec
	modBtfObjID    uint32
	structOpsProgs []*Program
}

// TODO: Doc
type structOpsProgMetaKey struct{}
type structOpsProgMeta struct {
	AttachBtfId btf.TypeID
	AttachType  sys.AttachType
	ModBtfObjID uint32
}

type structOpsLoader struct {
	prog2Map      map[string]string
	structOpsMaps map[string]*MapSpec
	usedProgs     map[string]bool
}

// NewStructOpsMapSpec builds a MapSpec for BPF_MAP_TYPE_STRUCT_OPS when
// the user-space value layout is *identical* to the kernel layout.
//
//	mapName        – name of the map to create (max 15 bytes like usual)
//	opsStructName  – base name of the ops struct, e.g. "bpf_dummy_ops"
//
// No public struct fields are modified: the required kernel-side type ID
// is hidden inside MapSpec.Contents[0].Value via structOpsMeta
func NewStructOpsMapSpec(mapName, opsStructName string) (*MapSpec, error) {
	s, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load vmlinux BTF: %w", err)
	}

	// 1. wrapper = struct bpf_struct_ops_<name>
	wrapperTyp, s, _, err := findStructByNameWithPrefix(s, opsStructName)
	if err != nil {
		return nil, err
	}

	wrapperSt := wrapperTyp.(*btf.Struct)
	wrapperID, _ := s.TypeID(wrapperTyp)

	userTyp, s, _, err := findStructTypeByName(s, opsStructName)
	if err != nil {
		return nil, err
	}
	userID, _ := s.TypeID(userTyp)
	userSt := userTyp.(*btf.Struct)

	spec := &structOpsSpec{
		typeId:       userID,
		data:         make([]byte, userSt.Size),
		programSpecs: make([]*ProgramSpec, len(userSt.Members)),
		kernFuncOff:  make([]uint32, len(userSt.Members)),
	}

	userSt, kern, err := resolveStructOpsTypes(s, spec)
	if err != nil {
		return nil, err
	}

	meta := &structOpsMeta{
		typeID:         wrapperID,
		secIdx:         0,
		varOffset:      0,
		userSize:       uint64(userSt.Size),
		progIdxMap:     make(map[string]int),
		attachBtfID:    make([]btf.TypeID, len(userSt.Members)),
		attachType:     make([]sys.AttachType, len(userSt.Members)),
		structOpsSpec:  spec,
		btf:            s,
		modBtfObjID:    kern.modBtf,
		structOpsProgs: make([]*Program, len(userSt.Members)),
	}

	return &MapSpec{
		Name:       mapName,
		Type:       StructOpsMap,
		KeySize:    4,
		ValueSize:  uint32(wrapperSt.Size),
		MaxEntries: 1,
		Contents:   []MapKV{{Key: 0, Value: meta}},
	}, nil
}

// findStructByNameWithPrefix looks up a BTF struct whose name is the given `name`
// prefixed by `structOpsValuePrefix` (“bpf_dummy_ops” → “bpf_struct_ops_bpf_dummy_ops”).
func findStructByNameWithPrefix(s *btf.Spec, name string) (btf.Type, *btf.Spec, uint32, error) {
	return findStructTypeByName(s, structOpsValuePrefix+name)
}

// findStructTypeByName iterates over *all* BTF types contained in the given Spec and
// returns the first *btf.Struct whose TypeName() exactly matches `name`.
func findStructTypeByName(s *btf.Spec, name string) (btf.Type, *btf.Spec, uint32, error) {
	if s == nil {
		return nil, nil, 0, fmt.Errorf("nil BTF: %w", btf.ErrNotFound)
	}
	if typ, err := s.AnyTypeByName(name); err == nil {
		if st, ok := typ.(*btf.Struct); ok {
			return st, s, 0, nil
		} // 0 = vmlinux
	} else if !errors.Is(err, btf.ErrNotFound) {
		return nil, nil, 0, fmt.Errorf("find in vmlinux: %w", err)
	}
	return findStructTypeByNameFromModule(s, name)
}

// findStructTypeByNameFromModule walks over the BTF info of loaded modules and
// searches for struct `name`.
func findStructTypeByNameFromModule(base *btf.Spec, name string) (btf.Type, *btf.Spec, uint32, error) {
	it := new(btf.HandleIterator)

	for it.Next() {
		defer it.Handle.Close()

		info, err := it.Handle.Info()
		if err != nil {
			return nil, nil, 0, fmt.Errorf("get info for BTF ID %d: %w", it.ID, err)
		}

		if !info.IsModule() {
			continue
		}

		spec, err := it.Handle.Spec(base)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("parse types for module %s: %w", info.Name, err)
		}

		typ, err := spec.AnyTypeByName(name)
		if errors.Is(err, btf.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, 0, fmt.Errorf("lookup type in module %s: %w", info.Name, err)
		}

		if t, ok := typ.(*btf.Struct); ok {
			return t, spec, uint32(it.ID), nil
		}
	}

	return nil, nil, 0, btf.ErrNotFound
}

// findStructOpsMapByOffset walks over a map-name→MapSpec map and returns the *first*
// Struct-Ops map whose variable resides in the ELF section `secIdx` **and**
// covers the relocation offset `offset`.
//
// The check uses the metadata embedded in MapSpec.Contents[0] (structOpsMeta):
//
//	secIdx      — section index of .struct_ops/.struct_ops.link
//	varOffset   — byte offset of the variable within that section
//	userSize    — sizeof(user-space struct)
//
// A match is:
//
//	(meta.SecIdx == secIdx)            &&
//	(meta.VarOffset ≤ offset < meta.VarOffset + meta.UserSize)
func findStructOpsMapByOffset(maps map[string]*MapSpec, secIdx int32, offset uint64) (*MapSpec, error) {
	for _, ms := range maps {
		if ms.Type != StructOpsMap || len(ms.Contents) == 0 {
			continue
		}

		meta := extractStructOpsMeta(ms.Contents)
		if meta == nil {
			continue // not a struct_ops map in the new format
		}

		if uint64(secIdx) == uint64(meta.secIdx) &&
			meta.varOffset <= offset &&
			(offset-meta.varOffset) < meta.userSize {
			return ms, nil
		}
	}
	return nil, fmt.Errorf("no struct_ops map found for secIdx %d and relOffset %d", secIdx, offset)
}

// findByTypeFromStruct searches the given BTF struct `st` for the *first* member
// whose BTF type **identity** equals `typ` (after resolving modifiers).
//
// The comparison is done via TypeID equality inside the same Spec, so a
// typedef chain that ultimately refers to the same concrete type will match.
func findByTypeFromStruct(spec *btf.Spec, st *btf.Struct, typ btf.Type) (*btf.Member, error) {
	typeId, err := spec.TypeID(typ)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve typeId for %s: %w", (typ).TypeName(), err)
	}

	for _, member := range st.Members {
		memberTypeId, err := spec.TypeID(member.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve typeId for %s: %w", member.Name, err)
		}
		if memberTypeId == typeId {
			return &member, nil
		}
	}

	return nil, fmt.Errorf("member of type %s not found in %s", typ.TypeName(), st.Name)
}

// getStructMemberIndexByOffset returns the *index* (0-based) of the struct member
// whose bit-offset equals the supplied `ofs`.
func getStructMemberIndexByOffset(s *btf.Struct, ofs uint64) int {
	for idx, member := range s.Members {
		if member.Offset == btf.Bits(ofs) {
			return idx
		}
	}
	return -1
}

// getStructMemberByName searches a BTF struct for a member whose Name equals `name`
// and returns a pointer to that member
func getStructMemberByName(s *btf.Struct, name string) (btf.Member, error) {
	for _, member := range s.Members {
		if member.Name == name {
			return member, nil
		}
	}
	return btf.Member{}, fmt.Errorf("member %s not found in struct %s", name, s.Name)
}

// getStructMemberIndexOf returns the index of `member` within struct `s` by
// comparing the member’s bit-offset.
func getStructMemberIndexOf(s *btf.Struct, member btf.Member) int {
	for idx, m := range s.Members {
		if m.Offset == member.Offset {
			return idx
		}
	}
	return -1
}

// extractStructOpsSpec returns the *structops.Spec that lives inside a MapSpec’s
// Contents slice.
//
// Background:
//
//	Struct-ops maps embed their bookkeeping information in
//	MapSpec.Contents[0].Value, which is a *structopsMeta. That Meta in turn
//	holds a pointer to the user-generated Spec.
func extractStructOpsSpec(contents []MapKV) *structOpsSpec {
	if meta := extractStructOpsMeta(contents); meta != nil {
		return meta.structOpsSpec
	}
	return nil
}

// extractStructOpsMeta returns the *structops.Meta embedded in a MapSpec’s Contents
// according to the struct-ops convention:
//
//	contents[0].Key   == uint32(0)
//	contents[0].Value == *structopsMeta
func extractStructOpsMeta(contents []MapKV) *structOpsMeta {
	if meta, ok := contents[0].Value.(*structOpsMeta); ok {
		return meta
	}
	return nil
}

// skipModsAndTypedefs returns the **next underlying type** by peeling off a
// single layer of “type wrappers” in BTF:
//
//   - btf.Typedef
//   - btf.Const
//   - btf.Volatile
//   - btf.Restrict
//
// If `typ` is already a concrete type (struct, int, ptr, etc.) it is returned
// unchanged.
func skipModsAndTypedefs(s *btf.Spec, typ btf.Type) (btf.Type, error) {
	typeID, err := s.TypeID(typ)
	if err != nil {
		return nil, fmt.Errorf("failed to find typeid of %s %w", typ.TypeName(), err)
	}

	t, err := s.TypeByID(typeID)
	if err != nil {
		return nil, fmt.Errorf("failed to find type by ID %d: %w", typeID, err)
	}

	switch tt := t.(type) {
	case *btf.Typedef:
		return btf.UnderlyingType(tt.Type), nil
	case *btf.Const:
		return btf.UnderlyingType(tt.Type), nil
	case *btf.Volatile:
		return btf.UnderlyingType(tt.Type), nil
	case *btf.Restrict:
		return btf.UnderlyingType(tt.Type), nil
	default:
		return t, nil
	}
}

// extendType creates a *new* byte‐slice that matches the memory layout of
// `dstTyp` by copying the overlapping fields from `srcData`, whose layout is
// described by `srcTyp`.
//
// Assumptions / behaviour
// -----------------------
//   - Both srcTyp and dstTyp must ultimately be *btf.Struct (typedef / const
//     wrappers are resolved via btf.UnderlyingType).
//   - The function matches members **by name**.  A member that exists in
//     dstTyp but not in srcTyp is left zero-initialised in the output buffer
//     (this is what the kernel expects for “new” fields).
//   - Bit-fields are *not* supported; if either side contains a bit-field
//     the function returns an error.
//   - Member size must be identical in src/dst; otherwise it is considered an
//     incompatible change and an error is returned.
func extendType(srcData []byte, srcTyp, dstTyp btf.Type) ([]byte, error) {
	srcSt, ok := btf.UnderlyingType(srcTyp).(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("extendType: (src) only struct → struct supported")
	}

	dstSt, ok := btf.UnderlyingType(dstTyp).(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("extendType: (dst) only struct → struct supported")
	}

	// allocate the buffer with the dst size, and zeroize
	out := make([]byte, dstSt.Size)

	srcByName := make(map[string]btf.Member, len(srcSt.Members))
	for _, srcMb := range srcSt.Members {
		srcByName[srcMb.Name] = srcMb
	}

	for _, dstMb := range dstSt.Members {
		srcMb, ok := srcByName[dstMb.Name]
		if !ok {
			// member not present in user struct. Leave zero
			continue
		}

		if srcMb.BitfieldSize > 0 || dstMb.BitfieldSize > 0 {
			return nil, fmt.Errorf("bitfield %s is not supported", dstMb.Name)
		}

		// calculate byte offset of src/dst
		szSrc, _ := btf.Sizeof(srcMb.Type)
		szDst, _ := btf.Sizeof(dstMb.Type)

		if szSrc != szDst {
			return nil, fmt.Errorf("size mismatch %s: %d vs %d", dstMb.Name, szSrc, szDst)
		}

		srcOff := int(srcMb.Offset / 8)
		dstOff := int(dstMb.Offset / 8)
		copy(out[dstOff:dstOff+szDst], srcData[srcOff:srcOff+szSrc])

	}

	return out, nil
}

// resolveStructOpsTypes fetches the **user-space struct** referenced by so.TypeId
// *and* the corresponding **kernel-space wrapper information**.
//
//  1. so.TypeId   → kernel BTF struct that represents the *user* definition
//  2. From that name, FindKernTypes() locates
//     • the actual kernel target struct (e.g. tcp_congestion_ops)
//     • the compiler-generated wrapper struct (bpf_struct_ops_<name>)
//     • the “data” member inside the wrapper that embeds the real ops
func resolveStructOpsTypes(kspec *btf.Spec, so *structOpsSpec) (*btf.Struct, *structOpsKernTypes, error) {
	uTyp, err := kspec.TypeByID(so.typeId)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve user type ID %d: %w", so.typeId, err)
	}

	userSt, ok := uTyp.(*btf.Struct)
	if !ok {
		return nil, nil, fmt.Errorf("type ID %d is not a struct", so.typeId)
	}

	kernInfo, err := findStructOpsKernTypes(kspec, userSt.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("kernel types for %s: %w", userSt.Name, err)
	}

	return userSt, kernInfo, nil
}

// findStructOpsKernTypes	discovers all kernel-side BTF artefacts related to a given
//
// *struct_ops* family identified by its **base name** (e.g. "tcp_congestion_ops").
func findStructOpsKernTypes(spec *btf.Spec, name string) (*structOpsKernTypes, error) {
	if spec == nil {
		return nil, fmt.Errorf("BTF spec shouldn't be nil")
	}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load vmlinux BTF: %w", err)
	}

	// 1. kernel target struct (e.g. tcp_congestion_ops)
	kType, s, modID, err := findStructTypeByName(spec, name)
	if err != nil {
		return nil, err
	}

	kStruct, ok := kType.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("kernType %s is not a Struct", kType.TypeName())
	}

	// 2. wrapper struct (bpf_struct_ops_<name>)
	wType, _, _, err := findStructByNameWithPrefix(s, name)
	if err != nil {
		return nil, err
	}

	wStruct, ok := wType.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("wrapperType %s is not a struct", wType.TypeName())
	}

	// 3. member “data” that embeds the real ops
	dataMem, err := findByTypeFromStruct(s, wStruct, kType)
	if err != nil {
		return nil, err
	}

	// 4. type-ID of kernel target
	kID, err := s.TypeID(kType)
	if err != nil {
		return nil, fmt.Errorf("type ID of %s: %w", kType.TypeName(), err)
	}

	// 5. type-ID of wrapper
	wID, err := s.TypeID(wType)
	if err != nil {
		return nil, fmt.Errorf("type ID of %s: %w", wType.TypeName(), err)
	}

	return &structOpsKernTypes{
		spec:        s,
		typ:         kStruct,
		typeID:      kID,
		valueType:   wStruct,
		valueTypeID: wID,
		dataMember:  dataMem,
		modBtf:      uint32(modID),
	}, nil
}

func createStructOpsMap(
	varSecInfo *btf.VarSecinfo,
	userStruct *btf.Struct,
	secIdx elf.SectionIndex,
	sec *elfSection,
) (*MapSpec, error) {

	// Retrieve raw data from the ELF section.
	// This data contains the initial values for the struct_ops map.
	raw, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read section data: %w", err)
	}

	vv, ok := varSecInfo.Type.(*btf.Var)
	if !ok {
		return nil, fmt.Errorf("VarSecinfo.Type is %T, want *btf.Var", varSecInfo.Type)
	}
	mapName := vv.Name

	// Set map flags based on the section name.
	// For the ".struct_ops.link" section, set the BPF_F_LINK flag.
	flags := uint32(0)
	if sec.Name == structOpsLinkSec {
		flags = sys.BPF_F_LINK
	}

	userSz := uint64(userStruct.Size)
	userOff := uint64(varSecInfo.Offset)
	if userOff+userSz > uint64(len(raw)) {
		return nil, fmt.Errorf("%s exceeds section", mapName)
	}
	initData := append([]byte(nil), raw[userOff:userOff+userSz]...)

	ms, err := NewStructOpsMapSpec(mapName, userStruct.Name)
	if err != nil {
		return nil, err
	}

	meta := extractStructOpsMeta(ms.Contents)
	if meta == nil {
		return nil, fmt.Errorf("createStructOpsMap: map %s is not initialized", ms.Name)
	}

	meta.name = ms.Name
	meta.secIdx = secIdx
	meta.varOffset = userOff
	meta.userSize = userSz

	copy(meta.structOpsSpec.data, initData)

	ms.Contents[0].Value = meta
	ms.Flags |= flags

	return ms, nil
}

func newStructOpsLoader() *structOpsLoader {
	return &structOpsLoader{
		prog2Map:      make(map[string]string),
		structOpsMaps: make(map[string]*MapSpec),
		usedProgs:     make(map[string]bool),
	}
}

// preLoad initializes the struct_ops map to align with the kernel's expectations.
// It maps the user-space struct_ops structure to the corresponding kernel-space structure,
// ensuring that all types, sizes, and data are correctly matched. The function processes
// each member of the user-defined struct, verifies compatibility with the kernel's struct,
// and sets up necessary program attachments for function pointers.
func (sl *structOpsLoader) preLoad(coll *CollectionSpec) error {
	for _, ms := range coll.Maps {
		if ms.Type != StructOpsMap {
			continue
		}

		/*
			meta, ok := extractStructOpsMeta(ms.Contents)
			if !ok {
				continue
			}

				_, kernInfo, err := resolveStructOpsTypes(meta.btf, meta.structOpsSpec)
				if err != nil {
					return err
				}

				// user -> kernel struct layout adjustment
					kernData, err := extendType(meta.structOpsSpec.Data, userSt, kernInfo.Type)
					if err != nil {
						return fmt.Errorf("%s: %w", ms.Name, err)
					}
		*/
		// initialize MapSpec for the user space map definition
		if err := sl.initMapSpec(ms); err != nil {
			return err
		}

		//meta.structOpsSpec.KernVData = kernData
		sl.structOpsMaps[ms.Name] = ms
	}

	return nil
}

// initMapSpec processes each member of the user-defined struct.
// It compares each member with the corresponding kernel struct member,
// handles function pointer members by setting up program attachments,
// and copies data members to the kernel data buffer.
func (sl *structOpsLoader) initMapSpec(ms *MapSpec) error {
	structOpsMeta := extractStructOpsMeta(ms.Contents)
	if structOpsMeta == nil {
		return fmt.Errorf("struct_ops metadata for %s not found", ms.Name)
	}

	structOps := extractStructOpsSpec(ms.Contents)
	if structOps == nil {
		return fmt.Errorf("struct_ops spec for %s not found", ms.Name)
	}

	// find user and kernel struct types
	userSt, kernTypes, err := resolveStructOpsTypes(structOpsMeta.btf, structOps)
	if err != nil {
		return err
	}

	vSize, err := btf.Sizeof(kernTypes.valueType)
	if err != nil {
		return fmt.Errorf("verify size of kern_value type: %s %w", kernTypes.typ.Name, err)
	}

	ms.ValueSize = uint32(vSize)
	structOpsMeta.btfVmlinuxValueTypeId = kernTypes.valueTypeID
	structOps.kernVData = make([]byte, kernTypes.valueType.Size)

	// process struct members
	if err := sl.copyDataMembers(userSt,
		kernTypes,
		structOps,
		structOpsMeta,
	); err != nil {
		return err
	}

	return nil
}

// copyDataMembers processes an individual member of the user-defined struct.
// It determines whether the member is a function pointer or data member,
// and handles it accordingly by setting up program attachments or copying data.
func (sl *structOpsLoader) copyDataMembers(
	userSt *btf.Struct,
	kern *structOpsKernTypes,
	structOps *structOpsSpec,
	structOpsMeta *structOpsMeta,
) error {
	data := structOps.data
	kernDataOff := kern.dataMember.Offset / 8
	kernData := structOps.kernVData[kernDataOff:]

	for idx, member := range userSt.Members {
		if err := sl.copyDataMember(
			idx,
			member,
			data, kernData,
			kern,
			structOps,
			structOpsMeta,
		); err != nil {
			return err
		}
	}

	return nil
}

// copyDataMember processes an individual member of the user-defined struct.
// It determines whether the member is a function pointer or data member,
// and handles it accordingly by setting up program attachments or copying data.
func (sl *structOpsLoader) copyDataMember(
	idx int,
	member btf.Member,
	data, kernData []byte,
	kern *structOpsKernTypes,
	structOps *structOpsSpec,
	structOpsMeta *structOpsMeta,
) error {
	memberName := member.Name
	memberOff := member.Offset / 8
	memberData := data[memberOff:]

	memberSize, err := btf.Sizeof(member.Type)
	if err != nil {
		return fmt.Errorf("failed to resolve the size of member %s: %w", memberName, err)
	}

	kernMember, err := getStructMemberByName(kern.typ, memberName)
	if err != nil {
		if isMemoryZero(memberData[:memberSize]) {
			// Skip if member doesn't exist in kernel BTF and data is zero
			return nil
		}
		return fmt.Errorf("member %s not found in kernel BTF and data is not zero", memberName)
	}

	kernMemberIdx := getStructMemberIndexOf(kern.typ, kernMember)
	if member.BitfieldSize > 0 || kernMember.BitfieldSize > 0 {
		return fmt.Errorf("bitfield %s is not supported", memberName)
	}

	kernMemberOff := kernMember.Offset / 8
	kernMemberData := kernData[kernMemberOff:]
	memberType, err := skipModsAndTypedefs(structOpsMeta.btf, member.Type)
	if err != nil {
		return fmt.Errorf("user: failed to skip typedefs for %s: %w", memberName, err)
	}

	kernMemberType, err := skipModsAndTypedefs(kern.spec, kernMember.Type)
	if err != nil {
		return fmt.Errorf("kern: failed to skip typedefs for %s: %w", kernMember.Name, err)
	}

	if _, ok := memberType.(*btf.Pointer); ok {
		// Handle function pointer member. set up the necessary attachments for function pointer members.
		// It associates the corresponding eBPF program with the member and updates the struct_ops specification.
		ps := structOps.programSpecs[idx]
		if ps == nil {
			return nil // skip if no program is assciated
		}

		if ps.Type != StructOps {
			return fmt.Errorf("member %s is not a valid struct_ops program", memberName)
		}

		if _, used := sl.usedProgs[ps.Name]; used {
			return fmt.Errorf("struct_ops: program %q is already used in other map", ps.Name)
		}
		sl.usedProgs[ps.Name] = true

		if prv, ok := sl.prog2Map[ps.Name]; ok && prv != structOpsMeta.name {
			return fmt.Errorf("struct_ops: program %q is referenced by maps %q and %q",
				ps.Name, prv, structOpsMeta.name)
		}

		structOpsMeta.progIdxMap[ps.Name] = idx
		structOpsMeta.attachBtfID[idx] = kern.typeID
		structOpsMeta.attachType[idx] = sys.AttachType(kernMemberIdx)

		kernFuncOff := kern.dataMember.Offset/8 + kern.typ.Members[kernMemberIdx].Offset/8
		structOps.kernFuncOff[idx] = uint32(kernFuncOff)

		ps.Instructions[0].Metadata.Set(structOpsProgMetaKey{}, &structOpsProgMeta{
			AttachBtfId: kern.typeID,
			AttachType:  sys.AttachType(kernMemberIdx),
			ModBtfObjID: kern.modBtf,
		})

		sl.prog2Map[ps.Name] = structOpsMeta.name

		return nil
	}

	// Handle data member. copy data members from the user-defined struct to the kernel data buffer.
	// It ensures that the sizes match between user and kernel types before copying the data.
	kernMemberSize, err := btf.Sizeof(kernMemberType)
	if err != nil || memberSize != kernMemberSize {
		return fmt.Errorf("size mismatch for member %s: %d != %d (kernel)", memberName, memberSize, kernMemberSize)
	}
	copy(kernMemberData[:memberSize], memberData[:memberSize])

	return nil
}

// onProgramLoaded is called right after a Program has been successfully
// loaded by collectionLoader.loadProgram().  If the program belongs to a
// struct_ops map it records the program for later FD-injection.
func (sl *structOpsLoader) onProgramLoaded(
	p *Program,
	progSpec *ProgramSpec,
	coll *CollectionSpec,
) error {

	mapName, ok := sl.prog2Map[p.name]
	if !ok {
		return nil
	}

	ms, ok := coll.Maps[mapName]
	if !ok {
		return fmt.Errorf("map %s is not loaded", mapName)
	}

	structOpsMeta := extractStructOpsMeta(ms.Contents)
	if structOpsMeta == nil {
		return fmt.Errorf("structOpsMeta for %s is not initialized", mapName)
	}

	progIdx := structOpsMeta.progIdxMap[p.name]
	attachType := structOpsMeta.attachType[progIdx]

	if int(attachType) > len(structOpsMeta.structOpsProgs) {
		return fmt.Errorf("program %s: unexpected attach type %d", p.name, attachType)
	}

	structOpsMeta.structOpsSpec.programSpecs[progIdx] = progSpec
	structOpsMeta.structOpsProgs[attachType] = p

	return nil
}

// postLoad runs after all maps and programs have been loaded.
// It writes program FDs into struct_ops.KernVData and updates the map entry.
func (sl *structOpsLoader) postLoad(maps map[string]*Map) error {
	for mapName, m := range maps {
		if m.Type() != StructOpsMap {
			continue
		}

		ms, ok := sl.structOpsMaps[mapName]
		if !ok {
			return fmt.Errorf("struct_ops Map: %s is not initialized", mapName)
		}

		structOps := extractStructOpsSpec(ms.Contents)
		if structOps == nil {
			return fmt.Errorf("postLoad: structOps is not initialized")
		}

		structOpsMeta := extractStructOpsMeta(ms.Contents)
		if structOpsMeta == nil {
			return fmt.Errorf("postLoad: structOps is not initialized")
		}

		for idx, prog := range structOpsMeta.structOpsProgs {
			if prog == nil {
				continue
			}
			defer prog.Close()

			off := structOps.kernFuncOff[idx]
			ptr := unsafe.Pointer(&structOps.kernVData[0])
			*(*uint64)(unsafe.Pointer(uintptr(ptr) + uintptr(off))) = uint64(prog.FD())
		}

		m := maps[mapName]

		zero := uint32(0)
		if err := m.Put(zero, structOps.kernVData); err != nil {
			return err
		}
	}
	return nil
}

// loadStructOpsMapsFromSections creates StructOps MapSpecs from DataSec sections
// ".struct_ops" and ".struct_ops.link" found in the object BTF.
func loadStructOpsMapsFromSec(
	s *btf.Spec,
	sections map[elf.SectionIndex]*elfSection,
	maps map[string]*MapSpec,
) error {
	for secIdx, sec := range sections {
		if sec.kind != structOpsSection {
			continue
		}

		// Process the struct_ops section to create the map
		if err := processStructOpsSection(s, secIdx, sec, maps); err != nil {
			return fmt.Errorf("failed to process StructOps section %s: %w", sec.Name, err)
		}
	}

	return nil
}

// callback to read relocations from a given section
type RelocReader func(sec *elf.Section, symbols []elf.Symbol) (map[uint64]elf.Symbol, error)

// collectStructOpsRelocations processes relocations targeting .struct_ops(.link)
// and associates the target function with the correct struct member in the map.
func collectStructOpsRelocations(
	sections map[elf.SectionIndex]*elfSection,
	maps map[string]*MapSpec,
	progs map[string]*ProgramSpec,
	relSecs map[elf.SectionIndex]*elf.Section,
	symbols []elf.Symbol,
	readRelosFn RelocReader,
) error {
	for _, sec := range relSecs {
		if !strings.HasPrefix(sec.Name, ".rel") {
			continue
		}

		relSec := sec
		targetIdx := elf.SectionIndex(sec.Info)
		targetSec, ok := sections[targetIdx]
		if !(ok && strings.HasPrefix(targetSec.Name, structOpsSec)) {
			continue
		}

		// Load the relocations from the relocation section
		rels, err := readRelosFn(relSec, symbols)
		if err != nil {
			return fmt.Errorf("failed to load relocations for section %s: %w", relSec.Name, err)
		}

		for relOff, sym := range rels {
			if err := processStructOpsRelo(maps, targetIdx, relOff, sym, progs); err != nil {
				return err
			}
		}
	}
	return nil
}

// processStructOpsSection walks the BTF Datasec for .struct_ops(.link) and
// creates a MapSpec per variable via createStructOpsMap.
func processStructOpsSection(
	objBTF *btf.Spec,
	secIdx elf.SectionIndex,
	sec *elfSection,
	maps map[string]*MapSpec,
) error {
	dt, err := objBTF.AnyTypeByName(sec.Name)
	if err != nil {
		return fmt.Errorf("datasec %s: %w", sec.Name, err)
	}
	ds, ok := dt.(*btf.Datasec)
	if !ok {
		return fmt.Errorf("%s BTF is not a Datasec", sec.Name)
	}

	for _, v := range ds.Vars {
		vv, ok := v.Type.(*btf.Var)
		if !ok {
			return fmt.Errorf("var type in %s: want *btf.Var, got %T", sec.Name, v.Type)
		}
		st, ok := btf.UnderlyingType(vv.Type).(*btf.Struct)
		if !ok {
			return fmt.Errorf("var %s: expect struct, got %T", vv.Name, vv.Type)
		}

		ms, err := createStructOpsMap(&v, st, secIdx, sec)
		if err != nil {
			return fmt.Errorf("create map for %s: %w", vv.Name, err)
		}
		maps[vv.Name] = ms
	}
	return nil
}

// processStructOpsRelo binds a ProgramSpec to the proper member index of the
// struct_ops map value, given a relocation against that map variable.
func processStructOpsRelo(
	maps map[string]*MapSpec,
	targetSec elf.SectionIndex,
	relOff uint64,
	sym elf.Symbol,
	progs map[string]*ProgramSpec,
) error {
	ms, err := findStructOpsMapByOffset(maps, int32(targetSec), relOff)
	if err != nil {
		return fmt.Errorf("find struct_ops map: %w", err)
	}

	structOps := extractStructOpsSpec(ms.Contents)
	if structOps == nil {
		return fmt.Errorf("map %s: no structOpsSpec", ms.Name)
	}
	structOpsMeta := extractStructOpsMeta(ms.Contents)
	if structOpsMeta == nil {
		return fmt.Errorf("map %s: no structOpsMeta", ms.Name)
	}

	uTyp, err := structOpsMeta.btf.TypeByID(structOps.typeId)
	if err != nil {
		return fmt.Errorf("TypeByID(%d) on map %s: %w", structOps.typeId, ms.Name, err)
	}
	uSt, ok := uTyp.(*btf.Struct)
	if !ok {
		return fmt.Errorf("type ID %d is not struct", structOps.typeId)
	}

	moff := relOff - structOpsMeta.varOffset
	memberIdx := getStructMemberIndexByOffset(uSt, moff*8)

	p, ok := progs[sym.Name]
	if !(ok && p.Type == StructOps) {
		return fmt.Errorf("program %q not found or not StructOps", sym.Name)
	}

	structOps.programSpecs[memberIdx] = p
	return nil
}

// check if the buffer is filled with 0
func isMemoryZero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}
