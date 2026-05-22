#include "gtest\gtest.h"

#include <utility/Logger.h>

int main(int argc, char** argv)
{
    CLoger::Initialize();
    CLoger::SetLogLevel(LOG_LEVEL::LOG_LEVEL_DEBUG);

	testing::InitGoogleTest(&argc, argv);
	RUN_ALL_TESTS();

    CLoger::UnInitialize();
	system("pause");
	return 0;
}