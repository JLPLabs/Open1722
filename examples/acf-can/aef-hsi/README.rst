AEF-HSI Tunneling
=================

Extends Open1722 with::

  * optional use of VLAN                   --vlan <4-byte-tag>
  * optional use of IPv6 UDP               --UDP6 <dest_addr>
  * optional use of CAN Brief              --canbrief
  * optional use of gPTP without full TSN  --gPTP

gPTP option uses "ACF User-defined" message type of 0x78 (where CAN is 0x01 and CAN Brief is 0x02)

We define 0x78 message type frame as an ACF payload that is a simplified version of ACF_CAN:

1. “Definition & Config” part (4 bytes): ``0xF0030000``
2. A timestamp (8 bytes): Use 9.4.3.10 (the same as used for message type 0x01 (CAN)
3. It **omits** CANID and CAN Payload
