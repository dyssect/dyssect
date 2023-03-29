define (
	$PORT			0,
	$BURST			32,
	$NDESC_IN		256,
	$NDESC_OUT		1024,
	$SHARDS			16,
	$SFC_LENGTH		2,
	$W 				7,
	$E 				1,
    $SLOp			1000,
	$SLOr			40000,
	$SOLVER			false,
)

controller :: DyssectController(
	PORT			$PORT,
	NDESC_IN		$NDESC_IN,
	NDESC_OUT		$NDESC_OUT,
	SHARDS			$SHARDS,
	SFC_LENGTH		$SFC_LENGTH,
	W 				$W,
	E				$E,
	SLOp			$SLOp,
	SLOr			$SLOr,
	SOLVER			$SOLVER,
)
StaticThreadSched(controller 8)

w0 :: DyssectWorkingCore(
	PORT 			$PORT,
	QUEUE			0,
	BURST 			$BURST,
)
w1 :: DyssectWorkingCore(
	PORT 			$PORT,
	QUEUE			1,
	BURST 			$BURST,
)
w2 :: DyssectWorkingCore(
	PORT 			$PORT,
	QUEUE			2,
	BURST 			$BURST,
)
w3 :: DyssectWorkingCore(
	PORT 			$PORT,
	QUEUE			3,
	BURST 			$BURST,
)
w4 :: DyssectWorkingCore(
	PORT 			$PORT,
	QUEUE			4,
	BURST 			$BURST,
)
w5 :: DyssectWorkingCore(
	PORT 			$PORT,
	QUEUE			5,
	BURST 			$BURST,
)
w6 :: DyssectWorkingCore(
	PORT 			$PORT,
	QUEUE			6,
	BURST 			$BURST,
)
o0 :: DyssectOffloadingCore(
	INDEX			0,
	QUEUE			7,
	BURST			$BURST
)
StaticThreadSched(w0 0)
StaticThreadSched(w1 1)
StaticThreadSched(w2 2)
StaticThreadSched(w3 3)
StaticThreadSched(w4 4)
StaticThreadSched(w5 5)
StaticThreadSched(w6 6)
StaticThreadSched(o0 7)

w0 -> 
	DyNAPT(HANDLE 0) ->
	EtherMirror() -> 
	DyssectQueueOut(PORT $PORT, QUEUE 0, BURST $BURST)
w1 ->
	DyNAPT(HANDLE 0) ->
	EtherMirror() -> 
	DyssectQueueOut(PORT $PORT, QUEUE 1, BURST $BURST)
w2 -> 
	DyNAPT(HANDLE 0) ->
	EtherMirror() -> 
	DyssectQueueOut(PORT $PORT, QUEUE 2, BURST $BURST)
w3 -> 
	DyNAPT(HANDLE 0) ->
	EtherMirror() -> 
	DyssectQueueOut(PORT $PORT, QUEUE 3, BURST $BURST)
w4 -> 
	DyNAPT(HANDLE 0) ->
	EtherMirror() -> 
	DyssectQueueOut(PORT $PORT, QUEUE 4, BURST $BURST)
w5 ->
	DyNAPT(HANDLE 0) ->
	EtherMirror() -> 
	DyssectQueueOut(PORT $PORT, QUEUE 5, BURST $BURST)
w6 ->
	DyNAPT(HANDLE 0) ->
	EtherMirror() -> 
	DyssectQueueOut(PORT $PORT, QUEUE 6, BURST $BURST)
o0 -> 
	DyNAPT(HANDLE 0) ->
	EtherMirror() -> 
	DyssectQueueOut(PORT $PORT, QUEUE 7, BURST $BURST)
