#!/bin/sh

# ========================================== #
#                                            #
#                  WARNING                   #
#              work in progress              #
#     do not use or rely on this script      #
#                                            #
# ========================================== #

DEV=${1:-/dev/cpu_fuzzer}
REC_SIZE="176"
TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT INT TERM

status_name() {
	case "${1}" in
		0) echo "EXEC_SUCCESS" ;;
		1) echo "EXEC_INVALID_OPCODE" ;;
		2) echo "EXEC_GP_FAULT" ;;
		3) echo "EXEC_PAGE_FAULT" ;;
		4) echo "EXEC_MSR_FAULT" ;;
		5) echo "EXEC_TIMEOUT" ;;
		6) echo "EXEC_UNKNOWN_FAULT" ;;
		*) echo "STATUS_${1}" ;;
	esac
}

trap_name() {
	case "${1}" in
		0) echo "-" ;;
		6) echo "#UD" ;;
		13) echo "#GP" ;;
		14) echo "#PF" ;;
		*) echo "vector_${1}" ;;
	esac
}

printf 'watching %s (record size %d bytes)\n' "${DEV}" "${REC_SIZE}" >&2

while :; do
	if ! dd if="${DEV}" of="${TMP}" bs=${REC_SIZE} count=1 2>/dev/null; then
		sleep 0.1
		continue
	fi
	bytes=$(wc -c <"${TMP}")
	if [ "${bytes}" -eq 0 ]; then
		sleep 0.1
		continue
	fi
	[ "${bytes}" -ne "${REC_SIZE}" ] && printf 'short read (%d bytes)\n' "${bytes}" >&2 && continue
	ts=$(od -An -N8 -tu8 "${TMP}" | tr -d ' ')
	status=$(od -An -j8 -N4 -tu4 "${TMP}" | tr -d ' ')
	len=$(od -An -j12 -N1 -tu1 "${TMP}" | tr -d ' ')
	trapno=$(od -An -j13 -N1 -tu1 "${TMP}" | tr -d ' ')
	regs_ok=$(od -An -j14 -N1 -tu1 "${TMP}" | tr -d ' ')
	set -- "$(od -An -v -j16 -N15 -tx1 "${TMP}" | tr -s ' ' ' ')"
	inst_bytes=""
	count=0
	for byte in "${@}"; do
		[ "${count}" -ge "${len}" ] && break
		inst_bytes="${inst_bytes} ${byte#0}" #here
		count=$((count + 1))
	done
	inst_bytes=${inst_bytes# }
	[ -z "${inst_bytes}" ] && inst_bytes="(empty)"
	regs_vals=$(od -An -j32 -N144 -tu8 "$TMP" | tr -s ' ' ' ')
	set -- "${regs_vals}"
	names="rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip rflags"
	i=1
	for name in ${names}; do
		eval "${name}=\${$i:-0}"
		i=$((i + 1))
	done
	ts_s=$(awk "BEGIN {printf \"%.6f\", $ts/1000000000}")
	status_text=$(status_name "${status}")
	trap_text=$(trap_name "${trapno}")
	if [ "${regs_ok}" -eq 1 ]; then
		rip_fmt=$(printf '0x%016x' "${rip}")
		rflags_fmt=$(printf '0x%016x' "${rflags}")
	else
		rip_fmt="--"
		rflags_fmt="--"
	fi
	printf '%s status=%s trap=%s regs=%s len=%u inst=[%s] rip=%s rflags=%s\n' \
		"${ts_s}"\
		"${status_text}"\
		"${trap_text}" \
		"$([ "${regs_ok}" -eq 1 ] && echo yes || echo no)" \
		"${len}"\
		"${inst_bytes}"\
		"${rip_fmt}"\
		"${rflags_fmt}"
done
