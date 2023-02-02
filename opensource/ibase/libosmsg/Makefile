include $(TOPDIR)/rules.mk

PKG_NAME:=libosmsg
PKG_RELEASE:=1
PKG_VERSION:=1.0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=libs
  CATEGORY:=TP-LINK ibase
  TITLE:=unix socket library
  DEPENDS:=
endef

define Package/$(PKG_NAME)/description
	Library for unix socket
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libosmsg.so $(1)/usr/lib
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) ./src/os_msg.h $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libosmsg.so $(1)/usr/lib
endef
$(eval $(call BuildPackage,$(PKG_NAME)))
