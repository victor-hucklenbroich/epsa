#ifndef ASAM_MCD3_API
#if defined (WIN32)
#ifdef ASAM_MCD3_DLL_EXPORT
#define ASAM_MCD3_API __declspec( dllexport )
#else
#define ASAM_MCD3_API __declspec( dllimport )
#pragma comment(lib, "MCD3D_DLL.lib")
#endif
#elif defined (__linux__)
#define ASAM_MCD3_API
#else
#pragma message ("Compiling MCD 3D Server: OS not supported")
#endif
#endif

#ifdef ASAM_MCD3_API
#include "asam-impl/MCD3D.h"
#endif

#include <iostream>
#include <memory>
#define POSITIVE_RSP    0x6F01
#define LOCAL_NEG_RSP   0x6F02
#define GLOBAL_NEG_RSP  0x6F03

using namespace asam::mcd;
using namespace asam::d;

long parseInput(size_t max) {
    std::string input;
    while (std::getline(std::cin, input)) {
        long i = std::stol(input);
        if (i >= 0 && i < max) {
            return i;
        }
        else if (i == -1) {
            return i;
        }

    }
    return 0;
}

int main() {
    MCDSystem* mcdSystem = MCDSystem::createInstance();
    {
        auto mcdVersion = std::unique_ptr<MCDVersion>(mcdSystem->getVersion());
        std::cout << "Init MCD3D Version: " << mcdVersion->getMajor() << "."
            << mcdVersion.get()->getMinor() << "." << mcdVersion->getRevision() << std::endl;
    }
    //MCDEventHandler eventHandler;
    //mcdSystem.setEventHandler(&eventHandler);
    {
        try {
            auto descr = std::unique_ptr<MCDDbProjectDescriptions>(mcdSystem->getDbProjectDescriptions());
            if (descr->getCount() == 0) {
                std::cout << "No MCDDbProjectDescriptions found!" << std::endl;
                std::cout << "Exiting MCD3D Server..." << std::endl;
                system("pause");
                return EXIT_FAILURE;
            }
            std::cout << "MCDDbProjectDescriptions:" << std::endl;
            for (size_t i = 0; i < descr->getCount(); ++i) {
                auto projectDescription = std::unique_ptr<MCDDbProjectDescription>(descr->getItemByIndex(i));
                std::cout << "  " << i << ".) " << projectDescription->getShortName() << std::endl;
            }
            auto descriptionIndex = parseInput(descr->getCount());
            auto projectDescription = std::unique_ptr<MCDDbProjectDescription>(descr->getItemByIndex(descriptionIndex));
            std::basic_string<char> projectName = projectDescription->getShortName();//"internalTestsuiteProject2_2_0";
            auto mcdProject = std::unique_ptr<MCDProject>(mcdSystem->selectProjectByName(projectName));
            mcdSystem->getActiveProject();
            if (mcdProject) {
                mcdSystem->prepareInterface();
                auto interfaces = std::unique_ptr<MCDInterfaces>(mcdSystem->getCurrentInterfaces());
                std::cout << "MCDInterfaces:" << std::endl;
                for (size_t i = 0; i < interfaces->getCount(); ++i) {
                    auto mcdInterface = std::unique_ptr<MCDInterface>(interfaces->getItemByIndex(i));
                    std::cout << "  " << i << ".) " << mcdInterface->getShortName() << std::endl;
                }
                auto interfaceIndex = parseInput(interfaces->getCount());
                auto mcdInterface = std::unique_ptr<MCDInterface>(interfaces->getItemByIndex(interfaceIndex));
                mcdInterface->connect();

                auto dbProject = std::unique_ptr<MCDDbProject>(mcdProject->getDbProject());
                //MCDDatatypeShortName vehicleInfo;
                {
                    auto dbVehicleInformations = std::unique_ptr<MCDDbVehicleInformations>(dbProject->getDbVehicleInformations());
                    if (dbVehicleInformations && dbVehicleInformations->getCount() > 0) {
                        std::cout << "Vehicle Informations:" << std::endl;
                        for (size_t i = 0; i < dbVehicleInformations->getCount(); ++i) {
                            auto dbVehicleInformation = std::unique_ptr<MCDDbVehicleInformation>(dbVehicleInformations->getItemByIndex(i));
                            MCDDatatypeShortName vehicleInfo = dbVehicleInformation->getShortName();
                            std::cout << "  " << i << ".) " << vehicleInfo << std::endl;
                        }
                        auto vehicleInformationIndex = parseInput(dbVehicleInformations->getCount());
                        auto dbVehicleInformation = std::unique_ptr<MCDDbVehicleInformation>(dbVehicleInformations->getItemByIndex(vehicleInformationIndex));
                        MCDDatatypeShortName vehicleInfo = dbVehicleInformation->getShortName();
                        dbVehicleInformation = std::unique_ptr<MCDDbVehicleInformation>(mcdProject->selectDbVehicleInformationByName(vehicleInfo));
                        /* {
                        auto dbVehicleInfos = std::unique_ptr<MCDDbVehicleInformations>(dbProject->getDbVehicleInformations());
                        if (dbVehicleInfos && dbVehicleInfos->getCount() > 0) {
                          auto dbVehicleInfo = std::unique_ptr<MCDDbVehicleInformation>(dbVehicleInfos->getItemByName(vehicleInfo));
                          mcdProject->selectDbVehicleInformation(*dbVehicleInfo);
                        }
                        }*/
                        do {
                            auto dbLogicalLinks = std::unique_ptr<MCDDbLogicalLinks>(dbVehicleInformation->getDbLogicalLinks());
                            std::cout << "Logical Links:" << std::endl;
                            for (size_t i = 0; i < dbLogicalLinks->getCount(); ++i) {
                                auto dbLink = std::unique_ptr<MCDDbLogicalLink>(dbLogicalLinks->getItemByIndex(i));
                                std::cout << "  " << i << ".) " << dbLink->getShortName()
                                    << " (" << dbLink->getProtocolType() << ")" << std::endl;

                            }
                            std::cout << "Enter -1 to come out of the Menu Option" << std::endl;
                            auto logicalLinkIndex = parseInput(dbLogicalLinks->getCount());
                            if (logicalLinkIndex == -1) {
                                break;
                            }
                            auto dbLink = std::unique_ptr<MCDDbLogicalLink>(dbLogicalLinks->getItemByIndex(logicalLinkIndex));
                            std::basic_string<char> logicalLinkName = dbLink->getShortName();//"LL_KPIT_BV1";
                            auto ll = std::unique_ptr<MCDLogicalLink>(mcdProject->createLogicalLinkByName(logicalLinkName));

                            std::cout << "Diag Services:" << std::endl;

                            auto dbLocation = std::unique_ptr<MCDDbLocation>(dbLink->getDbLocation());
                            auto dbServices = std::unique_ptr<MCDDbDiagServices>(dbLocation->getDbDiagServices());
                            do
                            {
                                for (size_t i = 0; i < dbServices->getCount(); ++i) {
                                    auto dbService = std::unique_ptr<MCDDbDiagService>(dbServices->getItemByIndex(i));
                                    std::cout << "  " << i << ".) " << dbService->getShortName() << std::endl;
                                }
                                std::cout << "Enter -1 to come out of the Menu Option" << std::endl;
                                auto diagServiceIndex = parseInput(dbServices->getCount());
                                if (diagServiceIndex == -1) {
                                    break;
                                }
                                auto dbService = std::unique_ptr<MCDDbDiagService>(dbServices->getItemByIndex(diagServiceIndex));

                                ll->open();
                                ll->gotoOnline();
                                std::basic_string<char> comPrimitiveName = dbService->getShortName();
                                auto comPrimitive = std::unique_ptr<MCDDiagComPrimitive>(ll->createDiagComPrimitiveByName(comPrimitiveName));

                                auto request = std::unique_ptr<MCDRequest>(comPrimitive->getRequest());
                                auto requestPdu = request->getPDU();
                                std::cout << "Request: 0x" << requestPdu.getValueAsString() << std::endl;

                                auto result = std::unique_ptr<MCDResult>(comPrimitive->executeSync());
                                auto responses = std::unique_ptr<MCDResponses>(result->getResponses());
                                if (responses->getCount() == 0) {
                                    std::cout << "No Response" << std::endl;
                                }
                                for (size_t i = 0; i < responses->getCount(); ++i) {
                                    auto response = std::unique_ptr<MCDResponse>(responses->getItemByIndex(i));
                                    auto responsePdu = response->getContainedResponseMessage();
                                    std::cout << i << ".) Response: 0x" << responsePdu.getValueAsString() << std::endl;
                                    auto dbResponse = std::unique_ptr<MCDDbResponse>(response->getDbObject());
                                    if (dbResponse->getResponseType() == POSITIVE_RSP) {
                                        std::cout << i << ".) Response Type: " << "Positive Response" << std::endl;
                                    }
                                    else if (dbResponse->getResponseType() == LOCAL_NEG_RSP) {
                                        std::cout << i << ".) Response Type: " << "Local Negative Response" << std::endl;
                                    }
                                    else if (dbResponse->getResponseType() == GLOBAL_NEG_RSP) {
                                        std::cout << i << ".) Response Type: " << "Global Negative Response" << std::endl;
                                    }
                                    else {
                                        std::cout << i << ".) Response Type: " << "Unknown Response" << std::endl;
                                    }
                                    auto responseParams = std::unique_ptr<MCDResponseParameters>(response->getResponseParameters());
                                    for (size_t j = 0; j < responseParams->getCount(); ++j) {
                                        auto responseParam = std::unique_ptr<MCDResponseParameter>(responseParams->getItemByIndex(j));
                                        std::cout << "  " << i << ".) " << responseParam->getShortName() << " = "
                                            << responseParam->getValue().getValueAsString() << std::endl;
                                    }
                                }
                            } while (1);
                            ll->close();
                            mcdProject->removeLogicalLink(*ll);
                        } while (1);
                        
                    }
                }
            }
            mcdProject->deselectVehicleInformation();
        }
        catch (MCDException& e) {
            auto error = std::unique_ptr<MCDError>(e.getError());
            std::cout << "Unexpected " << e.what() << ": " << error->getCodeDescription() << std::endl;
        }
    }
    mcdSystem->deselectProject();
    mcdSystem->unprepareInterface();
    MCDSystem::removeInstance(mcdSystem);
    return EXIT_SUCCESS;
}