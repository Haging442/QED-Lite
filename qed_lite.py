
def run_analysis(analysis, output_folder, profile_out=None):

    if profile_out is not None:
        pr = cProfile.Profile()
        pr.enable()

    report = analysis.gen_report(output_folder)

    if profile_out is not None:
        pr.disable()
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s).sort_stats('cumtime')
        ps.print_stats()

        with open(profile_out, 'w+') as f:
            f.write(s.getvalue())

    return report, report['metadata']["num_apps_after"] > 0


if __name__ == "__main__":
    from crypto_desc import CRYPTO_LIB
    import time
    import os
    import sys
    import cProfile, io, pstats
    from FileDependencyAnalysis import FileDependencyAnalysis
    import resource

    start = time.time()
    crypto_lib_desc = CRYPTO_LIB

    args = sys.argv[1:]

    if len(args) < 2:
        print('Usage: python3 qed_lite.py <scan_folder> <output_folder>')
        exit(1)
    else:
        scan_folder = args[0]
        output_folder = args[1]

    os.makedirs(output_folder, exist_ok=True)

    print("Running File-dependency Analysis")

    analysis = FileDependencyAnalysis(scan_folder, crypto_lib_desc, verbose=1)

    _, cont = run_analysis(analysis, output_folder, os.path.join(output_folder, 'result.prof'))

    print('Max RAM Usage', resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

    if not cont:
        print('No QV files found. Exiting.')
        exit(0)

    print("Done. Exiting...")
