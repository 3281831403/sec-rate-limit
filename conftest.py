"""pytest 根配置：把仓库根目录放进 sys.path，保证 ``import ratelimit`` 可用。

仓库离线运行、不依赖任何第三方 pytest 插件，因此这里只做路径准备。
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
