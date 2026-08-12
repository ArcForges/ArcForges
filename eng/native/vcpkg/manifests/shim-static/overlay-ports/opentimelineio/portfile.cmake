# SPDX-License-Identifier: AGPL-3.0-only

vcpkg_check_linkage(ONLY_STATIC_LIBRARY ONLY_DYNAMIC_CRT)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO AcademySoftwareFoundation/OpenTimelineIO
    REF "v0.18.1"
    SHA512 136f06ad7f9604b60d0463475f4a177ad8b7a18bc2ac74e5580a3f51fa728fa31cdb6e917c681d170460f685f4d1ec497f5e9ae8ed9952a3525fb69536a9412a
    HEAD_REF main
    PATCHES patches/0001-python-off-do-not-require-pybind11.patch
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DOTIO_CXX_INSTALL=ON
        -DOTIO_PYTHON_INSTALL=OFF
        -DOTIO_INSTALL_PYTHON_MODULES=OFF
        -DOTIO_INSTALL_COMMANDLINE_TOOLS=OFF
        -DOTIO_DEPENDENCIES_INSTALL=OFF
        -DOTIO_SHARED_LIBS=OFF
        -DOTIO_CXX_EXAMPLES=OFF
        -DOTIO_AUTOMATIC_SUBMODULES=OFF
        -DGIT_UPDATE_SUBMODULES=OFF
        -DOTIO_FIND_IMATH=ON
        -DOTIO_FIND_RAPIDJSON=ON
        -DBUILD_TESTING=OFF
    MAYBE_UNUSED_VARIABLES GIT_UPDATE_SUBMODULES
)
vcpkg_cmake_install()
vcpkg_copy_pdbs()
vcpkg_cmake_config_fixup(PACKAGE_NAME opentime CONFIG_PATH share/opentime)
vcpkg_cmake_config_fixup(PACKAGE_NAME opentimelineio CONFIG_PATH share/opentimelineio)
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE.txt" "${SOURCE_PATH}/NOTICE.txt")
