/*
 * NR5G MAC UL TB Stats (5G New Radio MAC Uplink Transport Block Statistics)
 *
 * File: mobileinsight.md (C source code format for parsing Qualcomm log packet 0xB881)
 *
 * This file defines the packet format structures and parsing logic used to decode
 * the 0xB881 log packet, which contains performance statistics for uplink transport blocks (UL TB)
 * at the MAC layer in 5G New Radio. The parser is designed to interface with the MobileInsight
 * core parsing engine, utilizing Python's C API to construct structured Python objects (lists/dicts)
 * containing the decoded fields.
 */

#include "consts.h"
#include "log_packet.h"
#include "log_packet_helper.h"

/*
 * NrMacUlTbStats_Fmt
 * 
 * Defines the layout of the subpacket header. The format specifies the data type, 
 * field name, and the field size in bytes.
 */
const Fmt NrMacUlTbStats_Fmt[] = {
    {UINT, "Minor Version", 2},           // 2-byte unsigned integer representing the minor version of the log packet
    {UINT, "Major Version", 2},           // 2-byte unsigned integer representing the major version of the log packet
    {UINT, "Sleep", 1},                   // 1-byte flag indicating sleep state
    {UINT, "Beam Change", 1},             // 1-byte indicator for beam configuration changes
    {UINT, "Signal Change", 1},           // 1-byte indicator for signal state changes
    {UINT, "DL Dynamic Cfg Change", 1},   // 1-byte indicator for downlink dynamic configuration changes
    {UINT, "DL Config", 1},               // 1-byte downlink configuration indicator
    {UINT, "UL Config", 1},               // 1-byte uplink configuration (lower 4 bits used for UL Config, upper 4 for ML1 State Change)
    {PLACEHOLDER, "ML1_State_Change", 0}, // 0-byte placeholder to be populated after splitting the UL Config byte
    {SKIP, NULL, 2},                      // 2 bytes of padding/reserved space
    {UINT, "Log Fields Change BMask", 2}, // 2-byte bitmask indicating which log fields have changed
    {SKIP, NULL, 1},                      // 1 byte of padding/reserved space
    {UINT, "Num Records", 1},             // 1-byte unsigned integer representing the number of TB records in this packet
    {SKIP, NULL, 4},                      // 4 bytes of padding/reserved space
};

/*
 * Records_v2_0
 * 
 * Format definition for individual Transport Block statistics records in Major Version 2, Minor Version 0.
 * Decodes little-endian byte streams and unsigned integers containing metrics like MCS, PRB, PHR, power, and TB counts.
 */
const Fmt Records_v2_0 [] = {
    {BYTE_STREAM_LITTLE_ENDIAN, "TB New Tx Bytes", 8}, // 8-byte little-endian stream: Bytes sent in new transmissions
    {BYTE_STREAM_LITTLE_ENDIAN, "TB ReTx Bytes", 8},   // 8-byte little-endian stream: Bytes sent in retransmissions
    {BYTE_STREAM_LITTLE_ENDIAN, "Num MCS", 8},         // 8-byte little-endian stream: Number of MCS indices / samples
    {BYTE_STREAM_LITTLE_ENDIAN, "Num PRB", 8},         // 8-byte little-endian stream: Number of Physical Resource Blocks
    {BYTE_STREAM_LITTLE_ENDIAN, "PHR", 8},             // 8-byte little-endian stream: Power Headroom Reports
    {UINT, "Total Power", 4},                          // 4-byte unsigned integer: Total transmission power
    {UINT, "Num New TX TB", 4},                        // 4-byte unsigned integer: Count of new transport blocks transmitted
    {UINT, "Num ReTx TB", 4},                          // 4-byte unsigned integer: Count of retransmitted transport blocks
    {UINT, "Num DTX ", 4},                             // 4-byte unsigned integer: Count of Discontinuous Transmission events
    {UINT, "Num RI", 4},                               // 4-byte unsigned integer: Count of Rank Indicator reports
    {UINT, "RI", 4},                                   // 4-byte unsigned integer: Rank Indicator value
    {UINT, "Num CQI", 4},                              // 4-byte unsigned integer: Count of Channel Quality Indicator reports
    {UINT, "CQI", 4},                                  // 4-byte unsigned integer: Channel Quality Indicator value
    {UINT, "Num PHR", 4},                              // 4-byte unsigned integer: Count of Power Headroom Reports
    {UINT, "TPC Accum", 4},                            // 4-byte unsigned integer: Accumulated Transmit Power Control commands
    {UINT, "Num ULSCH Sched", 4},                      // 4-byte unsigned integer: Number of Uplink Shared Channel scheduled occurrences
    {UINT, "Num No ULSCH Sched", 4},                   // 4-byte unsigned integer: Number of unscheduled Uplink Shared Channel occurrences
    {UINT, "Pcmax", 2},                                // 2-byte unsigned integer: Maximum configured output power
    {UINT, "Flush Gap Count", 2},                      // 2-byte unsigned integer: Count of flush gap events
};

/*
 * NrMacUlTbStatsRecord_v2_1
 * 
 * Format definition for individual Transport Block statistics records in Major Version 2, Minor Version 1.
 * Differs from version 2.0 (e.g., Total Power is 8 bytes, Pcmax is labeled 'Num Pcmax (dBm10)', and contains trailing padding).
 */
const Fmt NrMacUlTbStatsRecord_v2_1[] = {
    {UINT, "TB New Tx Bytes",     8}, // 8-byte unsigned integer: Bytes sent in new transmissions
    {UINT, "TB ReTx Bytes",     8},  // 8-byte unsigned integer: Bytes sent in retransmissions
    {UINT, "Num MCS",     8},         // 8-byte unsigned integer: Number of MCS indices / samples
    {UINT, "Num PRB",     8},         // 8-byte unsigned integer: Number of Physical Resource Blocks
    {UINT, "PHR",     8},             // 8-byte unsigned integer: Power Headroom Reports
    {UINT, "Total Power",     8},     // 8-byte unsigned integer: Total transmission power (increased from 4 bytes in v2.0)
    {UINT, "Num New Tx TB",     4},   // 4-byte unsigned integer: Count of new transport blocks transmitted
    {UINT, "Num ReTx TB",     4},     // 4-byte unsigned integer: Count of retransmitted transport blocks
    {UINT, "Num RI",     4},          // 4-byte unsigned integer: Count of Rank Indicator reports
    {UINT, "RI",     4},              // 4-byte unsigned integer: Rank Indicator value
    {UINT, "Num CQI",     4},         // 4-byte unsigned integer: Count of Channel Quality Indicator reports
    {UINT, "CQI",     4},             // 4-byte unsigned integer: Channel Quality Indicator value
    {UINT, "Num PHR",     4},         // 4-byte unsigned integer: Count of Power Headroom Reports
    {UINT, "TPC Accum",     4},       // 4-byte unsigned integer: Accumulated Transmit Power Control commands
    {UINT, "Num ULSCH Sched",     4}, // 4-byte unsigned integer: Number of Uplink Shared Channel scheduled occurrences
    {UINT, "Num No ULSCH Sched",     4}, // 4-byte unsigned integer: Number of unscheduled Uplink Shared Channel occurrences
    {UINT, "Num Pcmax (dBm10)",     2}, // 2-byte unsigned integer: Configured max transmitter power (in 1/10th dBm)
    {UINT, "Flush Gap Count",     2}, // 2-byte unsigned integer: Count of flush gap events
    {SKIP, NULL,                  4}, // 4-byte padding/reserved field at the end of the record
};

/**
 * _decode_nr_mac_ul_tb_stats_subpkt
 * 
 * Decodes the body/records of the NR5G MAC UL TB Stats subpacket according to its version.
 * 
 * @param b       Pointer to the raw byte buffer containing the packet payload.
 * @param offset  The current read offset (in bytes) within the buffer.
 * @param length  The total length of the raw byte buffer.
 * @param result  A PyObject list containing the header fields parsed prior to this call.
 *                The decoded records will be appended to this list.
 * 
 * @return The number of bytes successfully decoded/consumed in this execution.
 */
static int _decode_nr_mac_ul_tb_stats_subpkt(const char* b,
    int offset, size_t length, PyObject* result) {
    bool success = false;
    int start = offset; // Keep track of the starting offset to compute the total bytes read

    // Extract the header metadata previously decoded into the `result` list
    int major_ver = _search_result_int(result, "Major Version");
    int minor_ver = _search_result_int(result, "Minor Version");
    int n_record = _search_result_int(result, "Num Records");

    switch (major_ver) {
    case 2:
    {
        switch (minor_ver) {
        case 1: // Version 2.1
        {
            // Create a Python list to hold all individual records
            PyObject* result_allrecords = PyList_New(0);
            PyObject* t = NULL;

            // UL Config is a shared byte containing two 4-bit values:
            // Bits 0-3: UL Config
            // Bits 4-7: ML1 State Change
            int temp = _search_result_uint(result, "UL Config");
            int iUL = temp & 15;           // Bitmask 0x0F (lower 4 bits) to extract UL Config
            int iML = (temp >> 4) & 15;    // Shift right by 4 bits and mask 0x0F to extract ML1 State Change	

            // Replace the full-byte "UL Config" value in the result list with the isolated 4-bit value
            PyObject* old_object = _replace_result_int(result,
                "UL Config", iUL);
            Py_DECREF(old_object); // Decrease reference count of the discarded Python object to prevent memory leaks

            // Populates the "ML1_State_Change" placeholder in the result list with the isolated 4-bit value
            old_object = _replace_result_int(result,
                "ML1_State_Change", iML);
            Py_DECREF(old_object); // Decrease reference count of the discarded placeholder object

            // Decode each record sequentially
            for (int i = 0; i < n_record; i++) {
                PyObject* result_record = PyList_New(0);

                // Decode the record from buffer `b` at current `offset` according to the version 2.1 layout
                offset += _decode_by_fmt(NrMacUlTbStatsRecord_v2_1,
                    ARRAY_SIZE(NrMacUlTbStatsRecord_v2_1, Fmt),
                    b, offset, length, result_record);

                // Format the record name (e.g., "Record[0]", "Record[1]", etc.)
                char name[64];
                sprintf(name, "Record[%d]", i);

                // Build a Python tuple: (record_name, record_dict, type_label)
                t = Py_BuildValue("(sOs)", name, result_record, "dict");

                // Append the formatted tuple to the list containing all records
                PyList_Append(result_allrecords, t);

                // Clean up references to prevent memory leaks
                Py_DECREF(result_record);
                Py_DECREF(t);
            }

            // Package the list of all records as a Python tuple: ("Records List", records_list, "list")
            t = Py_BuildValue("(sOs)", "Records List", result_allrecords, "list");
            // Append it to the main result object
            PyList_Append(result, t);

            // Clean up temporary references
            Py_DECREF(t);
            Py_DECREF(result_allrecords);
            success = true;
            break;

        }
        case 0: // Version 2.0
        {
            // Create a Python list to hold all individual records
            PyObject* result_allrecords = PyList_New(0);
            PyObject* t = NULL;

            // Similar to version 2.1, extract and split the 8-bit UL Config field
            int temp = _search_result_uint(result, "UL Config");
            int iUL = temp & 15;           // Lower 4 bits: UL Config
            int iML = (temp >> 4) & 15;    // Upper 4 bits: ML1 State Change	
            PyObject* old_object = _replace_result_int(result,
                "UL Config", iUL);
            Py_DECREF(old_object);
            old_object = _replace_result_int(result,
                "ML1_State_Change", iML);
            Py_DECREF(old_object);

            // Decode each record sequentially
            for (int i = 0; i < n_record; i++) {
                // Records
                PyObject* result_Record = PyList_New(0);

                // Decode the record from buffer `b` at current `offset` according to the version 2.0 layout
                offset += _decode_by_fmt(Records_v2_0,
                    ARRAY_SIZE(Records_v2_0, Fmt),
                    b, offset, length, result_Record);

                /*
                 * Commented out custom parsing logic from the original implementation:
                 * Used to scale PHR (Power Headroom Report) values.
                 * 
                 * long long int temp1 = _search_result_ulongint(result_Record, "PHR");
                 * long long int iPHR = temp1*4294967296;  	
                 * PyObject* old_object = _replace_result_ulongint(result_Record, "PHR", iPHR);
                 * Py_DECREF(old_object); 
                 */
		                            
                // Format the record name
                char name[64];
                sprintf(name, "Record[%d]", i);

                // Build a Python tuple: (record_name, record_dict, type_label)
                t = Py_BuildValue("(sOs)", name, result_Record, "dict");

                // Append the formatted tuple to the list of all records
                PyList_Append(result_allrecords, t);

                // Clean up references
                Py_DECREF(result_Record);
                Py_DECREF(t);
            }
            // Records > result
            t = Py_BuildValue("(sOs)", "Records List", result_allrecords, "list");
            PyList_Append(result, t);
            Py_DECREF(t);
            Py_DECREF(result_allrecords);
            success = true;
            break;
        }
        default:
            break;
        }
    }
    default:
        break;

    }

    // Print warning/error if the packet version is unsupported
    if (!success) {
        printf("(MI)Unknown 5G NR MAC UL TB Stats: %d.%d\n", major_ver, minor_ver);
    }

    // Return the number of bytes parsed by subtracting the starting offset from the final offset
    return offset - start;
}
