"""Bounded first H1 MaterialTechnique/pass candidate after an owned set root.

Source: H1 MaterialTechniqueHeader (16B), followed by passCount native
MaterialPass (0x48B each). The parent must be the unique, fully validated
first type-15 XAsset root and its *first populated* slot must be inline-owned.
The cursor after the parent name is a serialization HYPOTHESIS, not a
relocated H1 source pointer. Never claim shader, argument, or pass ownership.
"""
import struct
from mwr_h1_clipmap_source import pointer_kind, INLINE
from mwr_h1_technique_order_source import ROOT_BYTES, TECHNIQUE_COUNT

HEADER_BYTES = 0x10
PASS_BYTES = 0x48
MAX_PASSES = 32
MAX_NAME = 256
MAX_ZERO_PAD = 15


def read_native_technique_candidate(data, at):
    """Check one native layout only; report no opaque source shader payloads."""
    if at < 0 or at + HEADER_BYTES > len(data):
        return None
    name_ptr, flags, n = struct.unpack_from('<QHH', data, at)
    if name_ptr != INLINE or not (1 <= n <= MAX_PASSES):
        return None
    end = at + HEADER_BYTES + n * PASS_BYTES
    if end > len(data):
        return None
    pass_reports = []
    for i in range(n):
        pos = at + HEADER_BYTES + i * PASS_BYTES
        shader_ptrs = struct.unpack_from('<5Q', data, pos)
        args_ptr = struct.unpack_from('<Q', data, pos + 64)[0]
        ptrs = shader_ptrs + (args_ptr,)
        if any(pointer_kind(v) == 'unrecognized_source_value' for v in ptrs):
            return None
        # At least one source shader reference is required for this probe.
        if not any(shader_ptrs[j] for j in (0, 2, 3, 4)):
            return None
        prim, obj, stable = struct.unpack_from('<BBB', data, pos + 41)
        total_args = prim + obj + stable
        if total_args > 128 or (total_args and not args_ptr):
            return None
        pass_reports.append({
            'pass_index': i,
            'shader_pointer_kinds': {
                key: pointer_kind(value)
                for key, value in zip(('vertex_shader', 'vertex_declaration',
                    'hull_shader', 'domain_shader', 'pixel_shader'), shader_ptrs)
            },
            'argument_pointer_kind': pointer_kind(args_ptr),
            'argument_count': total_args,
            'pixel_output_mask': data[pos + 40],
        })
    # Native inline name expected after the complete fixed pass array.
    # The original stream may serialize it elsewhere: that is an unresolved
    # case, not permission to scan farther and manufacture ownership.
    tail = data[end:min(len(data), end + MAX_NAME + 1)]
    zero = tail.find(b'\0')
    if not 1 <= zero <= MAX_NAME:
        return None
    name = tail[:zero]
    if not all(32 <= b < 127 for b in name):
        return None
    return {
        'source_technique_header_offset': at,
        'source_fixed_pass_array_end': end,
        'native_pass_stride': PASS_BYTES,
        'native_pass_count': n,
        'technique_flags': flags,
        'inline_technique_name_candidate': name.decode('ascii'),
        'source_technique_name_end': end + zero + 1,
        'first_passes': pass_reports[:4],
        'pass_count_checked': len(pass_reports),
        'shader_and_argument_pointers_not_relocated': True,
    }


def inspect_first_inline_technique_after_set(data, set_report):
    """Only inspect source positions justified by one verified parent set."""
    if set_report.get('status') != 'source_owned_first_type15_fixed_header_and_name_verified':
        return {'status': 'parent_technique_set_not_source_verified'}
    root = set_report.get('original_root_offset')
    end = set_report.get('source_name_end')
    if not isinstance(root, int) or not isinstance(end, int) or root < 0 or end < root + ROOT_BYTES:
        return {'status': 'invalid_parent_source_cursor'}
    if root + ROOT_BYTES > len(data) or end > len(data) or data[end-1] != 0:
        return {'status': 'parent_source_cursor_outside_prefix'}
    slot_bytes = data[root + 16:root + ROOT_BYTES]
    slots = struct.unpack('<240Q', slot_bytes)
    first = next(((i, p) for i, p in enumerate(slots) if p), None)
    if first is None:
        return {'status': 'no_populated_technique_slot'}
    index, tag = first
    kind = pointer_kind(tag)
    if kind != 'inline_owned':
        return {'status': 'first_populated_technique_slot_not_inline_owned',
                'first_populated_slot': index,
                'first_populated_pointer_kind': kind,
                'no_pass_arrays_admitted': True}
    matches = []
    for delta in range(MAX_ZERO_PAD + 1):
        at = end + delta
        if at > len(data):
            break
        if any(data[end:at]):
            break
        candidate = read_native_technique_candidate(data, at)
        if candidate is not None:
            matches.append({'source_cursor_zero_padding': delta, **candidate})
    if len(matches) != 1:
        return {
            'status': 'ambiguous_first_technique_cursor_candidates' if matches else
                      'first_inline_technique_not_found_under_bounded_cursor_model',
            'first_populated_slot': index,
            'candidate_count': len(matches),
            'no_pass_arrays_admitted': True,
        }
    return {
        'status': 'first_technique_native_layout_candidate_not_pointer_relocated',
        'first_populated_slot': index,
        'parent_source_name': set_report.get('source_name'),
        **matches[0],
        'no_pass_arrays_admitted': True,
        'NOTE': 'Fixed-layout source candidate only. No MaterialPass or shader XAsset binding is established.',
    }
