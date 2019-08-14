import logging
import logging.config

from cli.utils import get_swap_permission

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

c_handler = logging.StreamHandler()
f_handler = logging.FileHandler(get_swap_permission()+'.log')
c_handler.setLevel(logging.INFO)
f_handler.setLevel(logging.INFO)

c_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
f_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
c_handler.setFormatter(c_format)
f_handler.setFormatter(f_format)

logger.addHandler(c_handler)
logger.addHandler(f_handler)
