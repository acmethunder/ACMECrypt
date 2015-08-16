#!/usr/bin/env bash

xctool\
	clean\
	test\
	-project ACMECrypt/ACMECrypt.xcodeproj\
	-scheme AMCEAssymTests\
	-sdk iphonesimulator
