import matplotlib.pyplot as plt

# 应用名称
apps = ['Zoom', 'FaceTime', 'WhatsApp', 'Messenger', 'Discord']

# 三列百分比数据
standard_percent = [0.00, 72.40, 100.00, 98.90, 99.60]
proprietary_percent = [21.00, 1.60, 0.00, 1.10, 0.40]
proprietary_header_percent = [100 - (s + p) for s, p in zip(standard_percent, proprietary_percent)]

# 绘图
fig, ax = plt.subplots(figsize=(13, 6))  # 设置更宽的画布
bar_width = 0.5  # 设置柱子宽度
ax.bar(apps, standard_percent, label='Standard', color='green', width=bar_width)
ax.bar(apps, proprietary_header_percent, bottom=standard_percent, label='Proprietary+Standard', color='orange', width=bar_width)
ax.bar(apps, proprietary_percent,
       bottom=[s + h for s, h in zip(standard_percent, proprietary_header_percent)],
       label='Fully Proprietary', color='gray', width=bar_width)

# 设置图例和标签
ax.set_ylabel('Datagram Percentages (%)', fontsize=25)
# ax.set_xlabel('Applications', fontsize=25)
ax.set_ylim(0, 100)
ax.legend(loc='upper center', bbox_to_anchor=(0.45, 1.22), ncol=3, fontsize=24)
plt.xticks(rotation=0, fontsize=25)
plt.yticks(fontsize=25)
ax.set_xticks(range(len(apps)))
ax.set_xticklabels(apps, fontsize=25, ha='center')
plt.tight_layout()
plt.savefig('output.png')  # 保存为output.png图片

