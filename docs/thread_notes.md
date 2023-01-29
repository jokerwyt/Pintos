Q: How a thread gets to know who itself is.
A: By calling `thread_current`, which is feasible because of the design`only one page for a thread`. It could find its `struct thread` according to the current `%esp`.



Thread subsystem workflow







the cooperation between monitor locks and conditions



