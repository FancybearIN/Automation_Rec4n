#!/bin/bash

read -p "enter the path you have installed" path

# making the commands
echo "alias gg=bash $path/gf_sepraetor" >> ~/.zshrc   
echo "alias gg=bash $path/gf_sepraetor" >> ~/.bashrc   
# tool name command
echo "alias target=bash $path/stage1.sh" >> ~/.zshrc   
echo "alias target=bash $path/stage1.sh" >> ~/.bashrc   