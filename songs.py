import csv
import requests
from typing import Dict, Any, List

# API地址
API_URL = "https://www.diving-fish.com/api/maimaidxprober/music_data"


def fetch_music_data() -> List[Dict[str, Any]]:
    """从API获取歌曲数据"""
    try:
        response = requests.get(API_URL, timeout=10)
        response.raise_for_status()  # 检查请求是否成功
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"请求API失败: {e}")
        return []


def process_music_data(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """处理原始数据，生成每首歌曲每个难度一行的记录"""
    rows = []
    for song in data:
        song_id = song.get("id")
        title = song.get("title")
        category = song.get("basic_info", {}).get("genre", "")  # 分类：舞萌、其他游戏等
        song_type = song.get("type", "")  # 类别：SD或DX

        # ds（定数）和level（难度标签）数组长度应相同
        ds_list = song.get("ds", [])
        level_list = song.get("level", [])

        # 确保两个列表长度一致，以较短的为准
        min_len = min(len(ds_list), len(level_list))
        for i in range(min_len):
            row = {
                "歌曲id": song_id,
                "曲名": title,
                "分类": category,
                "难度标签": level_list[i],
                "定数": ds_list[i],
                "类别": song_type
            }
            rows.append(row)
    return rows


def save_to_csv(rows: List[Dict[str, Any]], filename: str = "maimai_songs.csv"):
    """将处理后的数据写入CSV文件"""
    if not rows:
        print("没有数据可写入")
        return

    fieldnames = ["歌曲id", "曲名", "分类", "难度标签", "定数", "类别"]
    try:
        with open(filename, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"成功写入 {len(rows)} 行数据到 {filename}")
    except IOError as e:
        print(f"写入文件失败: {e}")


def main():
    print("正在从API获取数据...")
    raw_data = fetch_music_data()
    if not raw_data:
        print("未获取到数据，脚本终止")
        return

    print(f"获取到 {len(raw_data)} 首歌曲，正在处理...")
    processed_rows = process_music_data(raw_data)

    save_to_csv(processed_rows)
    print("处理完成！")


if __name__ == "__main__":
    # 如果未安装requests，可使用以下代码安装（取消注释）
    # import subprocess
    # subprocess.check_call(["pip", "install", "requests"])
    main()