#!/system/bin/sh
MODDIR=${0%/*}
PKG=net.evecom.android.mztapp
for i in $(seq 1 60); do
  [ "$(getprop sys.boot_completed)" = "1" ] && break
  sleep 2
done
pm disable --user 0 $PKG/com.a.b.c.DECMsgDialog >/dev/null 2>&1
pm disable --user 0 $PKG/com.ijm.detect.drisk.IjiamiActivityOfflineAttack >/dev/null 2>&1
log -t MztKill "service.sh: DEC/Ijiami dialog components disabled"
