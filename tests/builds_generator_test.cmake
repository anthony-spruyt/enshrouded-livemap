# Each mutation of data/builds.json breaks one rule the generator enforces, so a bad row stops the
# configure step instead of shipping a table that hooks the wrong bytes.
#   cmake -DSOURCE_DIR=<repo> -DWORK_DIR=<scratch> -P tests/builds_generator_test.cmake

file(READ "${SOURCE_DIR}/data/builds.json" good)
file(MAKE_DIRECTORY "${WORK_DIR}")

function(generate name json out_rc out_error)
    file(WRITE "${WORK_DIR}/${name}.json" "${json}")
    file(REMOVE "${WORK_DIR}/${name}.h")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" "-DBUILDS_JSON=${WORK_DIR}/${name}.json" "-DBUILDS_OUT=${WORK_DIR}/${name}.h"
                -P "${SOURCE_DIR}/cmake/builds.cmake"
        RESULT_VARIABLE rc ERROR_VARIABLE error)
    string(REGEX REPLACE "[ \r\n]+" " " error "${error}")
    set(${out_rc} "${rc}" PARENT_SCOPE)
    set(${out_error} "${error}" PARENT_SCOPE)
endfunction()

function(expect_rejected name json phrase)
    generate("${name}" "${json}" rc error)
    if(rc EQUAL 0)
        message(SEND_ERROR "${name}: the generator accepted it")
    elseif(NOT error MATCHES "${phrase}")
        message(SEND_ERROR "${name}: rejected, but not for '${phrase}':\n${error}")
    elseif(EXISTS "${WORK_DIR}/${name}.h")
        message(SEND_ERROR "${name}: rejected, yet a header was written")
    endif()
endfunction()

function(mutate out json value)
    string(JSON mutated SET "${json}" ${ARGN} "${value}")
    set(${out} "${mutated}" PARENT_SCOPE)
endfunction()

generate(good "${good}" rc error)
if(NOT rc EQUAL 0 OR NOT EXISTS "${WORK_DIR}/good.h")
    message(SEND_ERROR "the shipped data/builds.json was rejected:\n${error}")
endif()

mutate(json "${good}" "4294967296" builds 0 time_date_stamp)
expect_rejected(stamp_over_32_bits "${json}" "does not fit 32 bits")

string(JSON stamp GET "${good}" builds 0 time_date_stamp)
string(JSON image_size GET "${good}" builds 0 size_of_image)
string(JSON label GET "${good}" builds 0 label)
mutate(json "${good}" "${stamp}" builds 1 time_date_stamp)
mutate(json "${json}" "\"${image_size}\"" builds 1 size_of_image)
expect_rejected(duplicate_fingerprint "${json}" "TimeDateStamp and SizeOfImage of another build")

mutate(json "${good}" "\"${label}\"" builds 1 label)
expect_rejected(duplicate_label "${json}" "is used twice")

mutate(json "${good}" "\"nonexistent\"" builds 0 sigset)
expect_rejected(unknown_sigset "${json}" "which is not defined")

mutate(json "${good}" "\"0x1000\"" builds 0 expected not_a_site)
expect_rejected(expected_site_outside_sigset "${json}" "not_a_site, which sigset launch does not have")

mutate(json "${good}" "\"0x1000\"" builds 3 expected_operands not_an_operand)
expect_rejected(expected_operand_outside_sigset "${json}" "not_an_operand, which sigset patch1 does not have")

string(JSON first_site GET "${good}" sigsets launch 0 site)
mutate(json "${good}" "\"${first_site}\"" sigsets launch 1 site)
expect_rejected(duplicate_site "${json}" "lists ${first_site} twice")

mutate(json "${good}" "\"4g 00\"" sigsets launch 0 bytes)
expect_rejected(malformed_bytes "${json}" "bytes '4g 00' is malformed")

mutate(json "${good}" "\"0x\"" sigsets launch 0 offset)
expect_rejected(malformed_offset "${json}" "offset '0x' is malformed")

mutate(json "${good}" "\"yes\"" sigsets launch 0 mandatory)
expect_rejected(mandatory_not_boolean "${json}" "mandatory must be true or false")

mutate(json "${good}" "\"0x1000\"" builds 3 expected_operands "Bad Name")
expect_rejected(malformed_operand_name "${json}" "name 'Bad Name' is malformed")
