# pcap2flowchart: pcap file convert to a flowchart figure
This program will read a signaling data which contains SIP/RTP/DNS/Diameter/M2UA protocols and convert it to a call trace flow chart.

You need to install php-cli, php-gd, wireshark and gnuplot libraries at first. (see install/Dockerfile)

The running command is as follows.

Example:

php pcap2flow.php your_pcap_file [wireshark filter string]


The output filename will be a PNG format with the first timestamp of your_pcap_file.