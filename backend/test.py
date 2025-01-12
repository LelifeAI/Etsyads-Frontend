from pathlib import Path

temperature_readings = [68, 65, 68, 70, 74, 72]

file_path = Path.home()/"temperatures.csv"
with file_path.open(mode="a", encoding="utf-8") as file:
    for temp in temperature_readings [0:]:
        file.write(f",{temp}")
