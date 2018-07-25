# https://github.com/nodejs/node-gyp/wiki/Linking-to-OpenSSL
{
  'variables': {
    # node v0.6.x doesn't give us its build variables,
    # but on Unix it was only possible to use the system OpenSSL library,
    # so default the variable to "true", v0.8.x node and up will overwrite it.
    'node_shared_openssl%': 'true'
  },
  'targets': [
    {
      'target_name': 'glue',
      'cflags': [
        '-std=c99',
        '-Wall',
        '-Wextra',
        '-Werror'
      ],
      'ldflags': [
        '-lcrypto'
      ],
      'sources': [
        'src/glue.c',
        'src/verify.c',
        'src/verify.h'
      ],
      'conditions': [
        ['node_shared_openssl=="false"', {
          # so when "node_shared_openssl" is "false", then OpenSSL has been
          # bundled into the node executable. So we need to include the same
          # header files that were used when building node.
          'include_dirs': [
            '<(node_root_dir)/deps/openssl/openssl/include'
          ],
          "conditions" : [
            ["target_arch=='ia32'", {
              "include_dirs": [ "<(node_root_dir)/deps/openssl/config/piii" ]
            }],
            ["target_arch=='x64'", {
              "include_dirs": [ "<(node_root_dir)/deps/openssl/config/k8" ]
            }],
            ["target_arch=='arm'", {
              "include_dirs": [ "<(node_root_dir)/deps/openssl/config/arm" ]
            }]
          ]
        }]
      ]
    }
  ]
}
