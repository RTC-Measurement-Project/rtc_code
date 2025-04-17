*DPI usage*

You shall have folders under this path: 

1) heuristic_baselines: the heuristic found protocols and their packet index

2) dpi_found: the packet / message details of each STUN / RTP / RTCP found in the pcap / pcapng by using dpi

3) accuracy_report: the precision and recall for each of the above pcap / pcapng processed



```
python check_dpi.py input_file_path
```

or 

```
python check_dpi.py input_folder_path
```


The first approach will generate a txt file under dpi_found. The second approach will generate a txt file for all pcap and pcapng files in the input_folder_path under dpi_found.

```
python cal_accuracy.py
```


This will go through each txt file under dpi_found folder and cross-check with the corresponding baselines in heuristic_baselines folder. Make sure you have a copy of baseline named as xxx_part1_streams.txt under folder heuristic_baselines.