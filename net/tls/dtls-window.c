/*
 * DTLS sliding window handling
 */
#define DTLS_EPOCH_SHIFT		(6 * CHAR_BIT)
#define DTLS_SEQ_NUM_MASK		0x0000FFFFFFFFFFFFL

#define DTLS_EMPTY_BITMAP (0xFFFFFFFFFFFFFFFFULL)

/* Handle DTLS sliding window
 * rv: rv < 0  drop packet
 *     rv == 0 OK
 */
static int dtls_window(struct tls_sock *tsk, const char *sn)
{
	__be64 *seq_num_ptr, *seq_num_last_ptr;
	u64 seq_num, seq_num_last;

	seq_num_ptr = (__be64 *)sn;
	seq_num_last_ptr = (__be64 *)tsk->iv_recv;

	seq_num = be64_to_cpu(*seq_num_ptr);
	seq_num_last = be64_to_cpu(*seq_num_last_ptr);

	if ((seq_num >> DTLS_EPOCH_SHIFT) != seq_num_last >> DTLS_EPOCH_SHIFT) {
		return -1;
	}

	seq_num &= DTLS_SEQ_NUM_MASK;

        /*
	 * tsk->dtls_window.next is the next *expected* packet (N), being
	 * the sequence number *after* the latest we have received.
	 *
	 * By definition, therefore, packet N-1 *has* been received.
	 * And thus there's no point wasting a bit in the bitmap for it.
	 *
	 * So the backlog bitmap covers the 64 packets prior to that,
	 * with the LSB representing packet (N - 2), and the MSB
	 * representing (N - 65). A received packet is represented
	 * by a zero bit, and a missing packet is represented by a one.
	 *
	 * Thus we can allow out-of-order reception of packets that are
	 * within a reasonable interval of the latest packet received.
	 */
	if (!tsk->dtls_window.have_recv) {
		tsk->dtls_window.next = seq_num + 1;
		tsk->dtls_window.bits = DTLS_EMPTY_BITMAP;
		tsk->dtls_window.have_recv = 1;
		return 0;
	} else if (seq_num == tsk->dtls_window.next) {
		/* The common case. This is the packet we expected next. */
		tsk->dtls_window.bits <<= 1;
		/* This might reach a value higher than 48-bit DTLS sequence
		 * numbers can actually reach. Which is fine. When that
		 * happens, we'll do the right thing and just not accept
		 * any newer packets. Someone needs to start a new epoch. */
		tsk->dtls_window.next++;
		return 0;
	} else if (seq_num + 65 < tsk->dtls_window.next) {
		/* Too old. We can't know if it's a replay */
		return -2;
	} else if (seq_num < tsk->dtls_window.next) {
		/* Within the sliding window, so we remember whether we've seen it or not */
		uint64_t mask = 1ULL << (tsk->dtls_window.next - seq_num - 2);
		if (!(tsk->dtls_window.bits & mask))
			return -3;
		tsk->dtls_window.bits &= ~mask;
		return 0;
	} else {
		/* The packet we were expecting has gone missing; this one is newer. */
		uint64_t delta = seq_num - tsk->dtls_window.next;

		if (delta >= 64) {
			/* We jumped a long way into the future. We have not seen
			 * any of the previous 32 packets so set the backlog bitmap
			 * to all ones. */
			tsk->dtls_window.bits = DTLS_EMPTY_BITMAP;
		} else if (delta == 63) {
			/* Avoid undefined behaviour that shifting by 64 would incur.
			 * The (clear) top bit represents the packet which is currently
			 * esp->seq - 1, which we know was already received. */
			tsk->dtls_window.bits = DTLS_EMPTY_BITMAP >> 1;
		} else {
			/* We have missed (delta) packets. Shift the backlog by that
			 * amount *plus* the one we would have shifted it anyway if
			 * we'd received the packet we were expecting. The zero bit
			 * representing the packet which is currently esp->seq - 1,
			 * which we know has been received, ends up at bit position
			 * (1<<delta). Then we set all the bits lower than that, which
			 * represent the missing packets. */
			tsk->dtls_window.bits <<= delta + 1;
			tsk->dtls_window.bits |= (1ULL << delta) - 1;
		}
		tsk->dtls_window.next = seq_num + 1;
		return 0;
	}
}
