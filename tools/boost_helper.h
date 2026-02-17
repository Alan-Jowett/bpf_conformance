// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <boost/version.hpp>
#if BOOST_VERSION < 108800
#include <boost/process.hpp>
#else
#define BOOST_PROCESS_VERSION 1
#include <boost/process/v1/args.hpp>
#include <boost/process/v1/child.hpp>
#include <boost/process/v1/exception.hpp>
#include <boost/process/v1/io.hpp>
#include <boost/process/v1/pipe.hpp>
#include <boost/process/v1/posix.hpp>
#endif
