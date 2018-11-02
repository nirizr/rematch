from .package import Package


server = Package(name='rematch-server', path='server', version_path='./',
                 classifiers=["Programming Language :: Python :: 2",
                              "Programming Language :: Python :: 2.7",
                              "Programming Language :: Python :: 3",
                              "Programming Language :: Python :: 3.4",
                              "Programming Language :: Python :: 3.5",
                              "Programming Language :: Python :: 3.6",
                              "Programming Language :: Python :: 3.7",
                              "Environment :: Web Environment",
                              "Framework :: Django"], zip_safe=True)

ida = Package(name='rematch-idaplugin', path='idaplugin',
              version_path='rematch', zip_safe=False,
              package_data={'idaplugin/rematch': ['images/*']},
              classifiers=["Programming Language :: Python :: 2",
                           "Programming Language :: Python :: 2.7"])

package_list = [server, ida]
