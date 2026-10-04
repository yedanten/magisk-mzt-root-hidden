#!/system/bin/sh
PKG=net.evecom.android.mztapp
pm enable --user 0 $PKG/com.a.b.c.DECMsgDialog >/dev/null 2>&1
pm enable --user 0 $PKG/com.ijm.detect.drisk.IjiamiActivityOfflineAttack >/dev/null 2>&1
log -t MztKill "uninstall.sh: dialog components re-enabled"
