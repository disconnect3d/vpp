## Introduction

Many features in VPP depend on access to the L4 header. Examples are (at least) access lists, NAT with port translation,
MAP-E/T and I am sure there are others. The host-stack, i.e. any packets destined for an address belonging to VPP itself,
must be fully reassembled. But for forwarding features, full reassembly is not always required. See definitions below.

Maintaining a flow is useful even for non-fragmented packets. Lots of features classify packets themselves into flows.
A flow in this context is a unidirectional set of packets within a specific timeslot that share the same properties.

- a fragment chain shares the same SA, DA, Protocol and Identifier fields
- a TCP flow shares the same SA, DA, Protocol and SP, DP fields.
- a GRE tunnel shares the same SA, DA, Protocol field
- IPv6 flows should be classified as a 4-tuple: same SA, DA, protocol and flow identifier fields

## Definitions

### Full reassembly

Each fragment in a fragment chain is buffered, and put in order, so with a new packet that is assembled from the individual
fragment packets as a result. The resulting packet (which may be splattered across a buffer chain) is then normalized.
All fragments in a chain must be received for a successful operation. Various security checks can be performed, like dropping
duplicate or overlapping fragments.

## Shallow virtual reassembly

If all fragments arrive in order, no buffering of packets is required. The L4 information in the first fragment is stored
and the remaining fragments in the chain is forwarded against this entry.

If fragments are out of order, or rather if the first fragment doesn't arrive first, individual fragments must be buffered until the
first fragment arrives. Then the same procedure as above is followed.

* Deep virtual reassembly

Deep virtual reassembly is more akin to full reassembly. All fragments in the chain is buffered, until reassembly can commence. All
checks for duplicate and overlapping fragments can be performed. The only difference is that the individual packets are kept, there no
resulting single packet, the "virtually reassembled" "result" of the set of packets is available in buffer meta data as a linked list 
with first and next buffer indicies.

## Requirements

All APIs and data structures must have C based unit tests.
TDD should be used.

## Implementation considerations


