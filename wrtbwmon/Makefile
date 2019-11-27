#
# Copyright (C) 2006-2019 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wrtbwmon
PKG_VERSION:=0.9.1
PKG_RELEASE:=3

include $(INCLUDE_DIR)/package.mk

define Package/wrtbwmon
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+busybox +iptables +ip
	TITLE:=A Traffic Usage Monitor
	SUBMENU:=Tools
	PKGARCH:=all
endef

define Package/wrtbwmon/description
	A traffic usage monitor client daemon based on bash script.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/wrtbwmon/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./net/usr/sbin/* $(1)/usr/sbin/
	
	$(INSTALL_DIR) $(1)/usr/share/wrtbwmon
	$(INSTALL_BIN) ./net/usr/share/wrtbwmon/* $(1)/usr/share/wrtbwmon/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./net/etc/init.d/wrtbwmon $(1)/etc/init.d/wrtbwmon

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./net/etc/config/wrtbwmon $(1)/etc/config/wrtbwmon
endef

$(eval $(call BuildPackage,wrtbwmon))
