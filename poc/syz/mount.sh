IMAGE=../../image/bullseye.img

mkdir mnt
mount -o loop $IMAGE ./mnt
mkdir ./mnt/root/poc_syz
cp -r ./use-* ./mnt/root/poc_syz/
cp -r ./slab-* ./mnt/root/poc_syz/
sleep 1
umount ./mnt
sleep 1
rm -r mnt
