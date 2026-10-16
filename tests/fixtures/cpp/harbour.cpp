// Harbour registry in C++.
#include <iostream>
#include <vector>
#include <string>

namespace harbour {

class Boat {
public:
    explicit Boat(std::string name) : name_(std::move(name)) {}
    const std::string& name() const { return name_; }
private:
    std::string name_;
};

int count_boats(const std::vector<Boat>& boats)
{
    return static_cast<int>(boats.size());
}

}  // namespace harbour

int main()
{
    std::vector<harbour::Boat> boats{harbour::Boat("Marie")};
    std::cout << harbour::count_boats(boats) << "\n";
}
