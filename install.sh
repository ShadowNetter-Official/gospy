#!/bin/bash

echo "gospy"
echo "by ShadowNetter"
echo
echo "cloning into repo..."
git clone https://github.com/ShadowNetter-Official/gospy
cd gospy/
echo "done"
echo
echo "building package..."
go build
echo "done"
echo
echo "installing gospy..."
sudo cp gosty /bin/
echo "done"
echo
echo "to remove gospy:"
echo "sudo rm /bin/gospy"
