#define BOOST_TEST_MODULE "wincrypt-utils tests"
//#define BOOST_TEST_MAIN
#include <boost/program_options.hpp>
#include <boost/test/unit_test.hpp>
#include "test_files.h"

static void parse_command_opts(int argc, char *argv[])
{
	boost::program_options::options_description opts("options");
	boost::program_options::variables_map vm;
	
	std::filesystem::path files_location;
	std::string log_level;
	
	opts.add_options()
		("test-files-dir", boost::program_options::value(&files_location), "test files directory path");
	
	boost::program_options::positional_options_description po;
	po.add("test-files-dir", 1);
	
	try
	{
		store(boost::program_options::command_line_parser(argc, argv).options(opts).positional(po).run(), vm);
		//store(parse_command_line(argc, argv, opts), vm);
		notify(vm);
	}
	catch (boost::program_options::error & ex)
	{
		std::cerr << ex.what() << std::endl;
		std::exit(EXIT_FAILURE);
	}
	
	if (not files_location.empty())
	{
		std::error_code ec;
		if (std::filesystem::exists(files_location, ec))
			test_files_location = files_location;
	}
}

struct GlobalFixture
{
	GlobalFixture()
	{
		auto argc = boost::unit_test::framework::master_test_suite().argc;
		auto argv = boost::unit_test::framework::master_test_suite().argv;

		parse_command_opts(argc, argv);
	}
	
	~GlobalFixture()
	{

	}
};

BOOST_GLOBAL_FIXTURE(GlobalFixture);
