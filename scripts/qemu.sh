KERNEL=../kernel/linux-4.19
IMAGE=../image/stretch.img
IMAGE=../image/bullseye.img

qemu-system-x86_64 \
	-m 8G \
	-cpu host \
	-smp sockets=1,cores=1 \
	-kernel $KERNEL/arch/x86/boot/bzImage \
	-append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 nokaslr" \
	-drive file=$IMAGE,format=raw \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-enable-kvm \
	-nographic \
	-pidfile vm.pid \
	2>&1 | tee vm.log
