debug: clean
	meson setup ./build -DPROFILE=true && ninja -C build

short: clean
	meson setup ./build -DSHORT=true && ninja -C build

release: clean
	meson setup ./build --buildtype release && ninja -C build

# 运行目标
run:
	sudo ./build/dpdk_qia $(pps) $(duration)

# 清理目标
clean:
	-rm -rf build
