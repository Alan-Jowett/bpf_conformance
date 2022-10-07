# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set (dependency_list ${CMAKE_SOURCE_DIR}/scripts/pre-commit ${CMAKE_SOURCE_DIR}/include/git_commit_id.h)

add_custom_target(setup_build ALL DEPENDS "${dependency_list}")

