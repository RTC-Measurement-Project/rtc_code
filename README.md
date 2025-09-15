<!-- filepath: /Users/sam/Desktop/rtc_code/README.md -->

# rtc_code

This project provides a collection of tools and scripts for analyzing RTC (Real-Time Communication) data. It includes functionalities for:

- Extracting and processing network packet streams (e.g., from .pcapng files).
- Identifying and filtering background network traffic.
- Analyzing RTC protocols (using custom Lua plugins for Wireshark).
- Generating metrics and compliance reports.
- Automating testing and data recording (as detailed in the `testbench` directory).

## Key Components

- `analyzer.py`, `protocol_extractor.py`, `measurement.py`: Core scripts for data processing and analysis.
- `step1_stream_grouping.py`, `step2_background_filtering_v2.py`, `step3-4_heuristic_baseline.py`: Scripts representing a multi-step analysis pipeline.
- `data/`: Contains raw packet capture data for various applications (Discord, FaceTime, Messenger, WhatsApp, Zoom).
- `metrics/`: Stores generated metrics, summaries, and distributions.
- `lua_plugins/`: Custom Lua scripts for Wireshark, to dissect specific protocols.
- `testbench/`: Tools and scripts for automating data collection and testing.
- `dpi/`: Deep Packet Inspection related scripts.

## Prerequisites/Installation

- Python 3.x
- Dependencies listed in `requirements.txt` and `testbench/requirements.txt`.
  - To install, run: `pip install -r requirements.txt` and `pip install -r testbench/requirements.txt`
- Wireshark for using Lua plugins.

## Usage

This section describes how to run the main scripts and workflows.

- **Configuration**: The project uses a `config.json` file for settings. `config_template.json` is provided as a starting point.
- **Analysis Pipeline**: The scripts `step1_stream_grouping.py`, `step2_background_filtering_v2.py` (note: `step2_background_filtering.py` also exists), and `step3-4_heuristic_baseline.py` constitute a sequential processing workflow.
- **Automated Testing**: The `testbench/` directory contains scripts like `auto_record.py` for automating data capture. Refer to `testbench/README.md` and `testbench/instruction.txt` for detailed instructions.
- **Individual Tools**: Scripts such as `analyzer.py`, `protocol_extractor.py`, and tools in the `tools/` directory are run individually for specific tasks.

Steps:

```bash
python step1_stream_grouping.py --config config.json --multiprocess --no-skip --recheck-asn
python step2_background_filtering_v2.py --config config.json --multiprocess
python step3-4_heuristic_baseline.py --config config.json --multiprocess
```

## Directory Structure

- **`/` (Root)**: Main analysis scripts, configuration, and requirements.
- **`data/`**: Raw input data (e.g., .pcapng files) categorized by application.
- **`dpi/`**: Scripts and resources related to Deep Packet Inspection.
- **`lua_plugins/`**: Lua scripts for protocol dissection with Wireshark.
- **`metrics/`**: Output directory for generated metrics, reports, and visualizations.
- **`testbench/`**: Tools and scripts for automating test procedures and data collection.
- **`tools/`**: Utility scripts for specific tasks like plotting or stream extraction.
- 

## Dataset

The collected traffic for IMC 2025 submission is accessible at: https://drive.google.com/drive/folders/1FOYysFErEFO4kzNuZHflKB6ICfWnhyHM?usp=sharing
