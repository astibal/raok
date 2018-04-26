PROJECT(raok)
cmake_minimum_required(VERSION 2.8)

# taken from http://public.kitware.com/Bug/view.php?id=12646
function(install_if_not_exists src dest)
  if(NOT IS_ABSOLUTE "${src}")
    set(src "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
  endif()
  get_filename_component(src_name "${src}" NAME)
  if (NOT IS_ABSOLUTE "${dest}")
    set(dest "${CMAKE_INSTALL_PREFIX}/${dest}")
  endif()
  install(CODE "
    if(NOT EXISTS \"\$ENV{DESTDIR}${dest}/${src_name}\")
      #file(INSTALL \"${src}\" DESTINATION \"${dest}\")
      message(STATUS \"Installing: \$ENV{DESTDIR}${dest}/${src_name}\")
      execute_process(COMMAND \${CMAKE_COMMAND} -E copy \"${src}\"
                      \"\$ENV{DESTDIR}${dest}/${src_name}\"
                      RESULT_VARIABLE copy_result
                      ERROR_VARIABLE error_output)
      if(copy_result)
        message(FATAL_ERROR \${error_output})
      endif()
    else()
      message(STATUS \"Skipping  : \$ENV{DESTDIR}${dest}/${src_name}\")
    endif()
  ")
endfunction(install_if_not_exists)


if(UNIX)
    SET(CMAKE_INSTALL_PREFIX /usr)
    
    
#    install(FILES raok.py DESTINATION bin 
#            PERMISSIONS 
#                    OWNER_READ OWNER_WRITE OWNER_EXECUTE 
#                    GROUP_READ GROUP_EXECUTE 
#                    WORLD_READ WORLD_EXECUTE 
#            RENAME raok
#    )

    install(FILES raok.py DESTINATION bin 
            PERMISSIONS 
                    OWNER_READ OWNER_WRITE OWNER_EXECUTE 
                    GROUP_READ GROUP_EXECUTE 
                    WORLD_READ WORLD_EXECUTE 
            RENAME raok
    )


    install_if_not_exists(etc/raok.cfg /etc/raok)
    install_if_not_exists(etc/dictionary /etc/raok)
    
    SET(CPACK_GENERATOR "DEB")
    SET(MAJOR_VERSION 0)
    SET(MINOR_VERSION 3)
    SET(PATCH_VERSION 3)
    SET(CPACK_PACKAGE_VERSION_MAJOR "${MAJOR_VERSION}")
    SET(CPACK_PACKAGE_VERSION_MINOR "${MINOR_VERSION}")
    SET(CPACK_PACKAGE_VERSION_PATCH "${PATCH_VERSION}")
    
    SET(CPACK_PACKAGE_DESCRIPTION "Raok is simple radius server for troubleshooting purposes")
    SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Raok accepts all access requests - for troubleshooting purposes only!")
    SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Ales Stibal <astib@mag0.net>")
    SET(CPACK_DEBIAN_PACKAGE_DEPENDS "python (>=2.7), python-pyrad")
    INCLUDE(CPack)    
    
    
endif()    
