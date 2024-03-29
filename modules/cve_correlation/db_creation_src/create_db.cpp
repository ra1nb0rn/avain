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

/**
 * Splits a string at the given character and stores the split strings in the given vector
 * @param str The str to split into individual strings
 * @param strs The vector the split string are to be stored in
 * @param ch The character that is to split the text into individual strings
 * @return the number of individual strings extracted
 */
std::size_t split_str(const std::string &str, std::vector<std::string> &strs, char ch) {
    size_t pos = str.find(ch);
    size_t initialPos = 0;
    strs.clear();

    // Iterate over the passed string
    while (pos != std::string::npos) {
        std::string split_word = str.substr(initialPos, pos - initialPos);
        if (split_word != "")
            strs.push_back(split_word);
        initialPos = pos + 1;

        pos = str.find(ch, initialPos);
    }

    // Add last split string
    strs.push_back(str.substr(initialPos, std::min(pos, str.length()) - initialPos + 1));

    return strs.size();
}

void transform_cpe23_to_cpe22(std::string &cpe23, std::string &cpe22) {
    cpe22 = "";
    cpe23 = cpe23.substr(8);  // cut off the beginning "cpe:2.3:"
    std::vector<std::string> cpe23_fields;
    split_str(cpe23, cpe23_fields, ':');

    // Cutoff the cpe23 string after 7 elements
    for (std::size_t i = 0; i < cpe23_fields.size(); i++) {
        if (i > 6)
            break;
        cpe22 += cpe23_fields[i] + ":";
    }
    cpe22 = cpe22.substr(0, cpe22.size() - 1);  // remove trailing ":"

    // Remove trailing "*" fields and replace inner "*" fields with "-"
    std::vector<std::string> cpe22_fields;
    split_str(cpe22, cpe22_fields, ':');
    bool remove_asterisks = true;
    for (int i = cpe22_fields.size() - 1; i >= 0; i--) {
        if (remove_asterisks && cpe22_fields[i] == "*") {
            cpe22_fields.erase(cpe22_fields.begin() + i);
        }
        else {
            if (cpe22_fields[i] == "*")
                cpe22_fields[i] = "-";
            remove_asterisks = false;
        }
    }

    // Put together the final CPE 2.2 string
    cpe22 = "cpe:/";
    for (auto const &field : cpe22_fields) {
        cpe22 += field + ":";
    }
    cpe22 = cpe22.substr(0, cpe22.size() - 1);  // remove trailing ":"
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
    SQLite::Statement cve_query(db, "INSERT INTO cve VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    SQLite::Statement cve_cpe_query(db, "INSERT INTO cve_cpe VALUES (?, ?, ?, ?, ?, ?, ?)");

    // read a JSON file
    std::ifstream input_file(filepath);
    json j;
    input_file >> j;

    json impact_entry;
    std::string cve_id, description, edb_ids, published, last_modified, vector_string, severity, cvss_version;
    std::string cpe, cpe23, descr_line, cpe_version, affected_versions, vendor_name, product_name, version_value;
    bool vulnerable;
    double base_score;

    // iterate the array
    for (auto &cve_entry : j["CVE_Items"]) {
        cve_id = cve_entry["cve"]["CVE_data_meta"]["ID"];
        edb_ids = "";

        description = "";
        for (auto &desc_entry : cve_entry["cve"]["description"]["description_data"]) {
            descr_line = desc_entry["value"];
            description += descr_line + "\n";
        }
        if (description != "")
            description.pop_back();

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
            base_score = -1;
            vector_string = "";
            cvss_version = "";
            severity = "";
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
        cve_query.bind(3, edb_ids);
        cve_query.bind(4, published);
        cve_query.bind(5, last_modified);
        
        // Assumption: every entry has at least a cvssV2 score
        cve_query.bind(6, cvss_version);
        cve_query.bind(7, base_score);
        cve_query.bind(8, vector_string);
        cve_query.bind(9, severity);

        cve_query.exec();
        cve_query.reset();
        
        cve_cpe_query.bind(1, cve_id);
        std::vector<VagueCpeInfo> vague_cpe_infos;

        for (auto &config_nodes_entry : cve_entry["configurations"]["nodes"]) {
            if (config_nodes_entry.find("cpe_match") != config_nodes_entry.end()) {
                for (auto &cpe_entry : config_nodes_entry["cpe_match"]) {
                    vulnerable = cpe_entry["vulnerable"];
                    if (!vulnerable)
                        continue;
                    cpe23 = cpe_entry["cpe23Uri"];
                    transform_cpe23_to_cpe22(cpe23, cpe);
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
                    // std::cerr << "Cannot parse CVE " << cve_id << " properly. Needs fixing!" << std::endl;
                    continue;
                }
                else if (config_nodes_entry["operator"] != "AND") {
                    // std::cerr << "Cannot parse CVE " << cve_id << " properly. Needs fixing!" << std::endl;
                    continue;
                }

                std::vector<std::unordered_set<VagueCpeInfo> > and_cpes;

                for (auto &children_entry : config_nodes_entry["children"]) {
                    std::unordered_set<VagueCpeInfo> cpes;
                    for (auto &cpe_entry : children_entry["cpe_match"]) {
                        vulnerable = cpe_entry["vulnerable"];
                        // if (!vulnerable)
                        //     continue;
                        cpe23 = cpe_entry["cpe23Uri"];
                        transform_cpe23_to_cpe22(cpe23, cpe);

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
        if (vague_cpe_infos.size() > 0 && cve_entry["cve"].find("affects") != cve_entry["cve"].end()) {
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

        db.exec("CREATE TABLE cve (cve_id VARCHAR(25), description TEXT, edb_ids TEXT, published DATETIME, last_modified DATETIME, \
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

        std::cout << "Creating local copy of NVD as " << outfile << " ..." << std::endl;
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
    std::cout << "Local copy of NVD created as " << db_abs_path << " ." << std::endl;
    free(db_abs_path);
    return EXIT_SUCCESS;
}
