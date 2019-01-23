# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_vpp_plugin(hanat-worker
  SOURCES
  worker/hanat_worker_db.c
  worker/hanat_worker_node.c
  worker/hanat_worker_slow_node.c
  worker/hanat_worker.c
  worker/hanat_worker_api.c

  API_FILES
  worker/hanat_worker.api

  INSTALL_HEADERS
  worker/hanat_worker_all_api_h.h
  worker/hanat_worker_msg_enum.h
)

add_vpp_executable(test_hanat_worker
  SOURCES worker/test_hanat_worker.c worker/hanat_worker_db.c
  LINK_LIBRARIES vppinfra
)

add_vpp_plugin(hanat-mapper
  SOURCES
  mapper/cli.c
  mapper/hanat_mapper.c
  mapper/hanat_mapper_api.c
  mapper/hanat_mapper_db.c
  mapper/hanat_state_sync.c
  mapper/node.c

  API_FILES
  mapper/hanat_mapper.api

  INSTALL_HEADERS
  mapper/hanat_mapper_all_api_h.h
  mapper/hanat_mapper_msg_enum.h
)
