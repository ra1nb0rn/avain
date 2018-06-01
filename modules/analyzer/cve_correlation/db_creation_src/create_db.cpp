#include <SQLiteCpp/SQLiteCpp.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <string>
#include <cstdlib>
#include <climits>

extern "C" {
    #include "dirent.h"
}

using json = nlohmann::json;

void handle_exception(SQLite::Exception &e) {
    std::string msg = e.what();
    if (msg.find("UNIQUE constraint failed") == std::string::npos) {
        throw e;
    }
}

int add_to_db(SQLite::Database &db, const std::string &filepath) {
    // Begin transaction
    SQLite::Transaction transaction(db);
    SQLite::Statement cve_cpe_query(db, "INSERT INTO cve_cpe VALUES (?, ?)");
    SQLite::Statement cve_query(db, "INSERT INTO cve VALUES (?, ?, ?, ?, ?, ?, ?, ?)");

    // read a JSON file
    std::ifstream input_file(filepath);
    json j;
    input_file >> j;

    json impact_entry;
    std::string cve_id, description, published, last_modified, vector_string, severity, cvss_version;
    std::string cpe, descr_line;
    bool vulnerable, no_cvss;
    double base_score;

    // iterate the array
    for (auto &cve_entry : j["CVE_Items"]) {
        cve_id = cve_entry["cve"]["CVE_data_meta"]["ID"];

        description = "";
        for (auto &desc_entry : cve_entry["cve"]["description"]["description_data"]) {
            descr_line = desc_entry["value"];
            description += descr_line + "\n";
        }
        if (description != "")
            description.pop_back();

        no_cvss = false;
        impact_entry = cve_entry["impact"];
        if (impact_entry.find("baseMetricV3") != impact_entry.end()) {
            base_score = (impact_entry["baseMetricV3"]["cvssV3"]["baseScore"]);
            vector_string = impact_entry["baseMetricV3"]["cvssV3"]["vectorString"];
            severity = impact_entry["baseMetricV3"]["cvssV3"]["baseSeverity"];
            cvss_version = impact_entry["baseMetricV3"]["cvssV3"]["version"];
        }
        else if (impact_entry.find("baseMetricV2") != impact_entry.end()) {
            base_score = impact_entry["baseMetricV2"]["cvssV2"]["baseScore"];
            vector_string = impact_entry["baseMetricV2"]["cvssV2"]["vectorString"];
            cvss_version = impact_entry["baseMetricV2"]["cvssV2"]["version"];
            severity = impact_entry["baseMetricV2"]["severity"];
        }
        else {
            no_cvss = true;
        }
        published = cve_entry["publishedDate"];
        std::replace(published.begin(), published.end(), 'T', ' ');
        std::replace(published.begin(), published.end(), 'Z', ':');
        published += "00";
        last_modified = cve_entry["lastModifiedDate"];
        std::replace(last_modified.begin(), last_modified.end(), 'T', ' ');
        std::replace(last_modified.begin(), last_modified.end(), 'Z', ':');
        last_modified += "00";

        cve_query.bind(1, cve_id);
        cve_query.bind(2, description);
        cve_query.bind(3, published);
        cve_query.bind(4, last_modified);
        
        // Assumption: every entry has at least a cvssV3 score
        cve_query.bind(5, cvss_version);
        cve_query.bind(6, base_score);
        cve_query.bind(7, vector_string);
        cve_query.bind(8, severity);

        cve_query.exec();
        cve_query.reset();

        cve_cpe_query.bind(1, cve_id);
        for (auto &config_nodes_entry : cve_entry["configurations"]["nodes"]) {
            for (auto &cpe_entry : config_nodes_entry["cpe"]) {
                vulnerable = cpe_entry["vulnerable"];
                if (!vulnerable)
                    continue;

                cpe = cpe_entry["cpe22Uri"];
                cve_cpe_query.bind(2, cpe);


                try {
                    cve_cpe_query.exec();
                }
                catch (SQLite::Exception& e) {
                    handle_exception(e);
                }

                try {
                    cve_cpe_query.reset();
                }
                catch (SQLite::Exception& e) {
                    handle_exception(e);
                }
            }
        }
    }

    // Commit transaction
    transaction.commit();
    return 1;
}

bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && 0 == str.compare(str.size()-suffix.size(), suffix.size(), suffix);
}

int main(int argc, char *argv[]) {

    if (argc != 3) {
        std::cerr << "Wrong argument count." << std::endl;
        std::cerr << "Usage: ./create_db cve_folder outfile" << std::endl;
        return EXIT_FAILURE;
    }

    std::string cve_folder = argv[1];
    std::string outfile = argv[2];
    std::string filename;
    std::vector<std::string> cve_files;


    auto start_time = std::chrono::high_resolution_clock::now();
    try {
        SQLite::Database db(outfile, SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE);

        db.exec("DROP TABLE IF EXISTS cve");
        db.exec("DROP TABLE IF EXISTS cve_cpe");

        db.exec("CREATE TABLE cve (cve_id VARCHAR(25), description TEXT, published DATETIME, last_modified DATETIME, cvss_version CHAR(3), base_score CHAR(3), vector VARCHAR(60), severity VARCHAR(15), PRIMARY KEY(cve_id))");
        db.exec("CREATE TABLE cve_cpe (cve_id VARCHAR(25), cpe TEXT, PRIMARY KEY(cve_id, cpe))");

        DIR *dir;
        struct dirent *ent;
        if ((dir = opendir(cve_folder.c_str())) != NULL) {
            while ((ent = readdir(dir)) != NULL) {
                filename = ent->d_name;
                if (ends_with(filename, ".json"))
                    cve_files.push_back(cve_folder + "/" + filename);  // only on unix platforms
            }
            closedir(dir);
        }
        else {
            // could not open directory
            std::cerr << "Could not open directory \'" << cve_folder << "\'" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "Creating CVE database " << outfile << " ..." << std::endl;
        for (const auto &file : cve_files) {
            add_to_db(db, file);
        }
    }
    catch (std::exception& e) {
        std::cerr << "exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    auto time = std::chrono::high_resolution_clock::now() - start_time;

    char *db_abs_path = realpath(outfile.c_str(), NULL);
    std::cout << "Database creation took " <<
    (float) (std::chrono::duration_cast<std::chrono::microseconds>(time).count()) / (1e6) << "s .\n";
    std::cout << "CVE database created as " << db_abs_path << " ." << std::endl;
    free(db_abs_path);
    return EXIT_SUCCESS;
}
