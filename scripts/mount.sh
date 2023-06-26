IMAGE=../image/bullseye.img
BOKASAN=../src/bokasan.ko

mkdir mnt
mount -o loop $IMAGE ./mnt
rm -f ./mnt/root/bokasan.ko
cp $BOKASAN ./mnt/root
echo "#!/bin/sh\ninsmod /root/bokasan.ko" > ./mnt/etc/rc.local
chmod 700 ./mnt/etc/rc.local
umount ./mnt
rm -r mnt
