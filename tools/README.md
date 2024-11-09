# PKT File Format

The PKT file format is a format that simplifies the input data for the EUCLID experiments by reducing the data to only what is required for the EUCLID system - the source and destination IPs. This allows the experiments to execute faster.

The PKT file format is a simple binary format which consists of:
1. A few metadata fields:
    - 8 bytes - "PKTV001X" -> Indicating the PKTV001X Extended file format - Literal ASCII
    - 8 bytes - uint64_t -> Number of entries in the file
    - 48 bytes - "0" -> Reserved metadata data area filled with 0s
2. For each of the ```n``` entries in the file:
    - 4 bytes - uint32_t -> The non-network ordered source IP address
    - 4 bytes - uint32_t -> The non-network ordered destination IP address
    - 4 bytes - uint32_t -> Reserved field 1 - **More info below**
    - 4 bytes - uint32_t -> Reserved field 2 - **More info below**

### Reserved fields

#### Reserved field 1

Empty for now.

#### Reserved field 2

The first bit indicates if the source IP address is a known malicious source.