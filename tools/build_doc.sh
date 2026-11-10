#! /bin/bash

# Copyright (c) 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

echo "***********************************************************************"
echo "RUNNING Doxygen code documentation tool"
echo "***********************************************************************"
echo "doxygen doxygen.ini"
if doxygen doxygen.ini ;
then
  [ ! -s Doxygen.log ]
  if [ $? -eq 0 ]
  then
  echo "***********************************************************************"
  echo "API documentation looks good!"
  echo "***********************************************************************"
    exit 0
  else
    cat Doxygen.log
    echo "***********************************************************************"
    echo "ERRORS found in the API documentation."
    echo "***********************************************************************"
    exit 1
  fi
else
  exit 1
fi

