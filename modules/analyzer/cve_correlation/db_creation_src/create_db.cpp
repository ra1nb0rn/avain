#include <SQLiteCpp/SQLiteCpp.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <string>
#include <cstdlib>
#include <climits>
#include <unordered_set>

extern "C" {
    #include "dirent.h"
}

using json = nlohmann::json;

struct VagueCpeInfo {
    std::string vague_cpe;
    std::string version_start;
    std::string version_start_type;
    std::string version_end;
    std::string version_end_type;

    bool operator==(const VagueCpeInfo &other) const {
        return vague_cpe == other.vague_cpe &&
                version_start == other.version_start &&
                version_start_type == other.version_start_type &&
                version_end == other.version_end &&
                version_end_type == other.version_end_type;
    }
};

namespace std {
    template<>
    struct hash<VagueCpeInfo> {
        std::size_t operator()(const VagueCpeInfo &vi) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return (hash<string>()(vi.vague_cpe)
                     ^ hash<string>()(vi.version_start)
                     ^ hash<string>()(vi.version_start_type)
                     ^ hash<string>()(vi.version_end)
                     ^ hash<string>()(vi.version_end_type));
        }
    };
}

void handle_exception(SQLite::Exception &e) {
    std::string msg = e.what();
    if (msg.find("UNIQUE constraint failed") == std::string::npos) {
        throw e;
    }
}

void get_specific_cpes(json &vendor_data, std::string &vague_cpe, std::unordered_set<VagueCpeInfo> &specific_cpes) {
    std::string cpe_part_str, cpe_str;
    for (auto &vendor_data_entry : vendor_data) {
        auto &vendor_name_ref = vendor_data_entry["vendor_name"];  // field must exist afaik
        if (vendor_data_entry.find("product") != vendor_data_entry.end()) {
            if (vendor_data_entry["product"].find("product_data") != vendor_data_entry["product"].end()) {
                for (auto &product_data_entry : vendor_data_entry["product"]["product_data"]) {
                    auto &product_name_ref = product_data_entry["product_name"];  // field must exist afaik
                    cpe_part_str = vendor_name_ref.get<std::string>() + ":" + product_name_ref.get<std::string>();
                    if (vague_cpe.find(cpe_part_str) != std::string::npos) {
                        if (product_data_entry.find("version") != product_data_entry.end()) {
                            if (product_data_entry["version"].find("version_data") != product_data_entry["version"].end()) {
                                for (auto &version_data_entry : product_data_entry["version"]["version_data"]) {
                                    if (version_data_entry.find("version_value") != version_data_entry.end()) {
                                        auto &version_value_ref = version_data_entry["version_value"];
                                        VagueCpeInfo vcpe = {vague_cpe + ":" + version_value_ref.get<std::string>(), "", "", "", ""};
                                        specific_cpes.emplace(vcpe);
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
}

int add_to_db(SQLite::Database &db, const std::string &filepath) {
    // Begin transaction
    SQLite::Transaction transaction(db);
    SQLite::Statement cve_query(db, "INSERT INTO cve VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    SQLite::Statement cve_cpe_query(db, "INSERT INTO cve_cpe VALUES (?, ?, ?, ?, ?, ?, ?)");

    // read a JSON file
    std::ifstream input_file(filepath);
    json j;
    input_file >> j;

    json impact_entry;
    std::string cve_id, description, published, last_modified, vector_string, severity, cvss_version;
    std::string cpe, descr_line, cpe_version, affected_versions, vendor_name, product_name, version_value;
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
        std::vector<VagueCpeInfo> vague_cpe_infos;

        for (auto &config_nodes_entry : cve_entry["configurations"]["nodes"]) {
            if (config_nodes_entry.find("cpe") != config_nodes_entry.end()) {
                for (auto &cpe_entry : config_nodes_entry["cpe"]) {
                    vulnerable = cpe_entry["vulnerable"];
                    if (!vulnerable)
                        continue;
                    cpe = cpe_entry["cpe22Uri"];
                    VagueCpeInfo vague_cpe_info = {cpe, "", "", "", ""};

                    if (cpe_entry.find("versionStartIncluding") != cpe_entry.end()) {
                        vague_cpe_info.version_start = cpe_entry["versionStartIncluding"];
                        vague_cpe_info.version_start_type = "Including";
                    }
                    else if (cpe_entry.find("versionStartExcluding") != cpe_entry.end()) {
                        vague_cpe_info.version_start = cpe_entry["versionStartExcluding"];
                        vague_cpe_info.version_start_type = "Excluding";
                    }

                    if (cpe_entry.find("versionEndIncluding") != cpe_entry.end()) {
                        vague_cpe_info.version_end = cpe_entry["versionEndIncluding"];
                        vague_cpe_info.version_end_type = "Including";
                    }
                    else if (cpe_entry.find("versionEndExcluding") != cpe_entry.end()) {
                        vague_cpe_info.version_end = cpe_entry["versionEndExcluding"];
                        vague_cpe_info.version_end_type = "Excluding";
                    }

                    if (vague_cpe_info.version_start != "" || vague_cpe_info.version_end != "") {
                        vague_cpe_infos.push_back(vague_cpe_info);
                    }

                    cve_cpe_query.bind(2, cpe);
                    cve_cpe_query.bind(3, vague_cpe_info.version_start);
                    cve_cpe_query.bind(4, vague_cpe_info.version_start_type);
                    cve_cpe_query.bind(5, vague_cpe_info.version_end);
                    cve_cpe_query.bind(6, vague_cpe_info.version_end_type);
                    cve_cpe_query.bind(7, "");

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
            else if (config_nodes_entry.find("children") != config_nodes_entry.end()) {
                if (config_nodes_entry.find("operator") == config_nodes_entry.end()) {
                    std::cerr << "Cannot parse CVE " << cve_id << " properly. Needs fixing!" << std::endl;
                    continue;
                }
                else if (config_nodes_entry["operator"] != "AND") {
                    std::cerr << "Cannot parse CVE " << cve_id << " properly. Needs fixing!" << std::endl;
                    continue;
                }

                std::vector<std::unordered_set<VagueCpeInfo> > and_cpes;

                for (auto &children_entry : config_nodes_entry["children"]) {
                    std::unordered_set<VagueCpeInfo> cpes;
                    for (auto &cpe_entry : children_entry["cpe"]) {
                        vulnerable = cpe_entry["vulnerable"];
                        // if (!vulnerable)
                        //     continue;
                        cpe = cpe_entry["cpe22Uri"];

                        VagueCpeInfo vague_cpe_info = {cpe, "", "", "", ""};

                        if (cpe_entry.find("versionStartIncluding") != cpe_entry.end()) {
                            vague_cpe_info.version_start = cpe_entry["versionStartIncluding"];
                            vague_cpe_info.version_start_type = "Including";
                        }
                        else if (cpe_entry.find("versionStartExcluding") != cpe_entry.end()) {
                            vague_cpe_info.version_start = cpe_entry["versionStartExcluding"];
                            vague_cpe_info.version_start_type = "Excluding";
                        }

                        if (cpe_entry.find("versionEndIncluding") != cpe_entry.end()) {
                            vague_cpe_info.version_end = cpe_entry["versionEndIncluding"];
                            vague_cpe_info.version_end_type = "Including";
                        }
                        else if (cpe_entry.find("versionEndExcluding") != cpe_entry.end()) {
                            vague_cpe_info.version_end = cpe_entry["versionEndExcluding"];
                            vague_cpe_info.version_end_type = "Excluding";
                        }

                        if (vague_cpe_info.version_start != "" || vague_cpe_info.version_end != "") {
                            get_specific_cpes(cve_entry["cve"]["affects"]["vendor"]["vendor_data"], cpe, cpes);
                        }

                        cpes.emplace(vague_cpe_info);

                    }
                    and_cpes.emplace_back(cpes);
                }
                for (int i = 0; i < and_cpes.size(); i++) {
                    for (auto &cpe_outer : and_cpes[i]) {
                        std::string and_str = "";
                        for (int j = 0; j < and_cpes.size(); j++) {
                            if (i == j)
                                continue;
                            for (auto &cpe_inner : and_cpes[j]) {
                                and_str += cpe_inner.vague_cpe + ",";
                            }
                        }
                        if (and_str != "")
                           and_str.pop_back();

                        cve_cpe_query.bind(2, cpe_outer.vague_cpe);
                        cve_cpe_query.bind(3, cpe_outer.version_start);
                        cve_cpe_query.bind(4, cpe_outer.version_start_type);
                        cve_cpe_query.bind(5, cpe_outer.version_end);
                        cve_cpe_query.bind(6, cpe_outer.version_end_type);
                        cve_cpe_query.bind(7, and_str);

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
                        }
                    }
                }
            }
        }

        std::string cpe_part_str, cpe_str;
        if (vague_cpe_infos.size() > 0) {
            for (auto &vendor_data_entry : cve_entry["cve"]["affects"]["vendor"]["vendor_data"]) {
                auto &vendor_name_ref = vendor_data_entry["vendor_name"];  // field must exist afaik
                if (vendor_data_entry.find("product") != vendor_data_entry.end()) {
                    if (vendor_data_entry["product"].find("product_data") != vendor_data_entry["product"].end()) {
                        for (auto &product_data_entry : vendor_data_entry["product"]["product_data"]) {
                            auto &product_name_ref = product_data_entry["product_name"];  // field must exist afaik
                            cpe_part_str = vendor_name_ref.get<std::string>() + ":" + product_name_ref.get<std::string>();
                            for (VagueCpeInfo &vi : vague_cpe_infos) {
                                if (vi.vague_cpe.find(cpe_part_str) != std::string::npos) {                                        
                                    if (product_data_entry.find("version") != product_data_entry.end()) {
                                        if (product_data_entry["version"].find("version_data") != product_data_entry["version"].end()) {
                                            for (auto &version_data_entry : product_data_entry["version"]["version_data"]) {
                                                if (version_data_entry.find("version_value") != version_data_entry.end()) {
                                                    auto &version_value_ref = version_data_entry["version_value"];
                                                    cpe_str = vi.vague_cpe + ":" + version_value_ref.get<std::string>();

                                                    cve_cpe_query.bind(2, cpe_str);
                                                    cve_cpe_query.bind(3, "");
                                                    cve_cpe_query.bind(4, "");
                                                    cve_cpe_query.bind(5, "");
                                                    cve_cpe_query.bind(6, "");

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
                                    }
                                    break;
                                }
                            }
                        }
                    }
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

        db.exec("CREATE TABLE cve (cve_id VARCHAR(25), description TEXT, published DATETIME, last_modified DATETIME, \
            cvss_version CHAR(3), base_score CHAR(3), vector VARCHAR(60), severity VARCHAR(15), PRIMARY KEY(cve_id))");
        db.exec("CREATE TABLE cve_cpe (cve_id VARCHAR(25), cpe TEXT, cpe_version_start VARCHAR(255), cpe_version_start_type VARCHAR(50), \
            cpe_version_end VARCHAR(255), cpe_version_end_type VARCHAR(50), with_cpes TEXT, PRIMARY KEY(cve_id, cpe, cpe_version_start, \
            cpe_version_start_type, cpe_version_end, cpe_version_end_type, with_cpes))");

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
