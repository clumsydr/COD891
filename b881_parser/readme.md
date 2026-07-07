0xB881 is a Statistics Log rather than a per-slot schedule log, almost all of these fields are cumulative counters. They continuously add up from the moment the modem connects to the network.


1. Payload Volume Metrics (The "Goodput" vs. "Badput")
TB New Tx Bytes (8 Bytes): Transport Block New Transmission Bytes.
    The cumulative total of fresh, original IP payload bytes (including TCP ACKs) your phone has uploaded. This is the metric we used in the final Python script to map upload throughput.

TB ReTx Bytes (8 Bytes): Transport Block Retransmission Bytes.
    The cumulative total of bytes the modem had to resend because the cell tower failed to decode them the first time. A high number here indicates severe RF interference or a weak signal.


2. Physical Resource Metrics (The Airwaves)
{"Num MCS", 8}: Cumulative Modulation and Coding Scheme.
    This is a running sum of the MCS index used for every transmission. To find your average MCS over a 1-second window, you take the delta of this field and divide it by the delta of the total Transport Blocks sent.

{"Num PRB", 8}: Cumulative Physical Resource Blocks.
    A running sum of the exact frequency bandwidth allocated to your phone.


3. Transport Block Counters (The "Boxes")
{"Num New TX TB", 4}: Count of New Transport Blocks.
    How many individual "boxes" of fresh data have been shipped.

{"Num ReTx TB", 4}: Count of Retransmitted Transport Blocks.
    How many individual "boxes" had to be shipped a second time.

{"Num DTX", 4}: Count of Discontinuous Transmissions.
    DTX occurs when the base station schedules an uplink resource for your phone, but your phone fails to transmit anything (often because it missed the downlink control message telling it to do so).


4. Uplink Control Information (UCI / Feedback)
These last fields represent the feedback your phone is giving the cell tower about the Downlink signal quality, which is multiplexed into your uplink transmissions.
{"Num RI", 4} & {"RI", 4}: Rank Indicator (Count & Cumulative Value).
    RI tells the base station how many spatial MIMO layers the phone can currently distinguish. If RI is 4, the phone is saying, "The signal is so clean I can download 4 separate data streams at the exact same time."

{"Num CQI", 4} & {"CQI", 4}: Channel Quality Indicator (Count & Cumulative Value).
    A score from 1 to 15 rating the overall cleanliness of the downlink RF environment. The base station uses your CQI to decide how fast your download speeds should be.



