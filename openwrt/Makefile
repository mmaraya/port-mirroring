##############################################
# OpenWrt Makefile for port-mirroring package
# https://github.com/mmaraya/port-mirroring
##############################################

include $(TOPDIR)/rules.mk

PKG_NAME:=port-mirroring
PKG_VERSION:=1.4.2
PKG_RELEASE:=1
PKG_MAINTAINER:=Mike Maraya <mike.maraya@gmail.com>
PKG_LICENSE:=BSD-2-Clause
PKG_LICENSE_FILES:=LICENSE
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/mmaraya/port-mirroring.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=f6ead68b7760fa86e8da73ac1e062349f243ac93
PKG_FIXUP:=autoreconf
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/port-mirroring
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+libpcap +libpthread
	TITLE:=port-mirroring
	URL:=https://github.com/mmaraya/port-mirroring
	MENU:=1
endef

define Package/port-mirroring/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/port-mirroring $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/port-mirroring.conf $(1)/etc/config/port-mirroring
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/port-mirroringd $(1)/etc/init.d/port_mirroring
endef

define Package/port-mirroring/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	echo "Enabling rc.d symlink for port-mirroring"
	/etc/init.d/port_mirroring enable
fi
exit 0
endef

define Package/port-mirroring/prerm
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
	echo "Removing rc.d symlink for port-mirroring"
	/etc/init.d/port_mirroring disable
fi
exit 0
endef

$(eval $(call BuildPackage,port-mirroring))

