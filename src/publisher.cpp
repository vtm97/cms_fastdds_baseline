#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/topic/Topic.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "CmsMessage.hpp"
#include "CmsMessagePubSubTypes.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <time.h>

using namespace eprosima::fastdds::dds;

namespace
{

uint64_t monotonic_time_ns()
{
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

struct Options
{
    uint32_t domain_id = 0;
    std::string topic_name = "CmsTopic";
    uint32_t node_id = 1;
    uint32_t flow_id = 1;

    uint64_t count = 1000;

    uint32_t payload_bytes = 256;
    uint32_t period_ms = 16;

    uint32_t start_delay_ms = 0;
    uint32_t min_readers = 1;
};

void print_usage(const char* program)
{
    std::cout
        << "Usage:\n"
        << "  " << program
        << " [--domain-id N]"
        << " [--topic-name NAME]"
        << " [--node-id N]"
        << " [--flow-id N]"
        << " [--count N]"
        << " [--payload-bytes N]"
        << " [--period-ms N]\n"
        << " [--start-delay-ms N]"
        << " [--min-readers N]\n";
}

bool parse_arguments(
        int argc,
        char** argv,
        Options& options)
{
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--domain-id" && i + 1 < argc)
        {
            options.domain_id =
                    static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--topic-name" && i + 1 < argc)
        {
            options.topic_name = argv[++i];
        }
        else if (arg == "--node-id" && i + 1 < argc)
        {
            options.node_id =
                    static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--flow-id" && i + 1 < argc)
        {
            options.flow_id =
                    static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--count" && i + 1 < argc)
        {
            options.count =
                    std::stoull(argv[++i]);
        }
        else if (arg == "--payload-bytes" && i + 1 < argc)
        {
            options.payload_bytes =
                    static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--period-ms" && i + 1 < argc)
        {
            options.period_ms =
                    static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--start-delay-ms" && i + 1 < argc)
        {
            options.start_delay_ms =
                    static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--min-readers" && i + 1 < argc)
        {
            options.min_readers =
                    static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--help")
        {
            print_usage(argv[0]);
            std::exit(0);
        }
        else
        {
            std::cerr << "Unknown or incomplete argument: "
                      << arg << '\n';
            return false;
        }
    }

    if (options.min_readers == 0)
    {
        std::cerr << "min-readers must be >= 1.\n";
        return false;
    }

    if (options.payload_bytes > 4096)
    {
        std::cerr
            << "payload-bytes must be <= 4096 because CmsMessage.idl "
            << "defines sequence<octet, 4096>.\n";

        return false;
    }

    return true;
}

class CmsPublisher
{
private:

    class PublisherListener : public DataWriterListener
    {
    public:

        std::atomic_int matched{0};

        void on_publication_matched(
                DataWriter*,
                const PublicationMatchedStatus& info) override
        {
            matched = info.current_count;

            if (info.current_count_change > 0)
            {
                std::cout
                    << "[DDS] CMS subscriber matched. "
                    << "current readers = "
                    << info.current_count
                    << '\n';
            }
            else if (info.current_count_change < 0)
            {
                std::cout
                    << "[DDS] CMS subscriber unmatched. "
                    << "current readers = "
                    << info.current_count
                    << '\n';
            }
        }
    };

    DomainParticipant* participant_ = nullptr;
    Publisher* publisher_ = nullptr;
    Topic* topic_ = nullptr;
    DataWriter* writer_ = nullptr;

    TypeSupport type_;

    PublisherListener listener_;

public:

    CmsPublisher()
        : type_(new cms::CmsMessagePubSubType())
    {
    }

    ~CmsPublisher()
    {
        if (publisher_ != nullptr && writer_ != nullptr)
        {
            publisher_->delete_datawriter(writer_);
        }

        if (participant_ != nullptr && publisher_ != nullptr)
        {
            participant_->delete_publisher(publisher_);
        }

        if (participant_ != nullptr && topic_ != nullptr)
        {
            participant_->delete_topic(topic_);
        }

        if (participant_ != nullptr)
        {
            DomainParticipantFactory::get_instance()
                    ->delete_participant(participant_);
        }
    }

    bool init(const Options& options)
    {
        if (DomainParticipantFactory::get_instance()
                ->load_XML_profiles_file(
                    "../config/qos_baseline.xml") != RETCODE_OK)
        {
            std::cerr
                << "Failed to load QoS XML: "
                << "../config/qos_baseline.xml\n";

            return false;
        }

        std::cout
            << "Loaded QoS XML: "
            << "../config/qos_baseline.xml\n";
        // 1. Join configured domain
        participant_ =
                DomainParticipantFactory::get_instance()
                        ->create_participant(
                            options.domain_id,
                            PARTICIPANT_QOS_DEFAULT);

        if (participant_ == nullptr)
        {
            std::cerr
                << "Failed to create DomainParticipant.\n";
            return false;
        }

        // 2. Register CmsMessage type
        if (type_.register_type(participant_) != RETCODE_OK)
        {
            std::cerr
                << "Failed to register CmsMessage type.\n";
            return false;
        }

        // 3. Create DDS Topic
        topic_ =
                participant_->create_topic(
                    options.topic_name,
                    type_.get_type_name(),
                    TOPIC_QOS_DEFAULT);

        if (topic_ == nullptr)
        {
            std::cerr
                << "Failed to create topic: "
                << options.topic_name
                << '\n';
            return false;
        }

        // 4. Create Publisher
        publisher_ =
                participant_->create_publisher(
                    PUBLISHER_QOS_DEFAULT);

        if (publisher_ == nullptr)
        {
            std::cerr
                << "Failed to create Publisher.\n";
            return false;
        }

        // 5. Create DataWriter
        writer_ =
                publisher_->create_datawriter_with_profile(
                    topic_,
                    "cms_writer_profile",
                    &listener_);

        if (writer_ == nullptr)
        {
            std::cerr
                << "Failed to create DataWriter.\n";
            return false;
        }

        std::cout
            << "Fast DDS publisher initialized.\n"
            << "Domain: " << options.domain_id << '\n'
            << "Topic : " << options.topic_name << '\n';

        return true;
    }

    void run(const Options& options)
    {
        std::cout
            << "\nPublisher configuration:\n"
            << "domain_id     = " << options.domain_id << '\n'
            << "topic_name    = " << options.topic_name << '\n'
            << "node_id       = " << options.node_id << '\n'
            << "flow_id       = " << options.flow_id << '\n'
            << "count         = " << options.count << '\n'
            << "payload_bytes = " << options.payload_bytes << '\n'
            << "period_ms     = " << options.period_ms << '\n'
            << "min_readers    = " << options.min_readers << '\n'
            << '\n';

        std::cout
            << "Waiting for CMS subscriber...\n";

        while (listener_.matched.load() <
               static_cast<int>(options.min_readers))
        {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(100));
        }

        if (options.start_delay_ms > 0)
        {
            std::cout
                << "Waiting "
                << options.start_delay_ms
                << " ms before transmission.\n";

            std::this_thread::sleep_for(
                std::chrono::milliseconds(
                    options.start_delay_ms));
        }

        std::cout
            << "Starting transmission.\n";

        cms::CmsMessage message;

        message.node_id(options.node_id);
        message.flow_id(options.flow_id);

        // 1 = sensor
        message.traffic_type(1);

        std::vector<uint8_t> payload(
            options.payload_bytes,
            0xAB);

        message.payload(payload);

        auto next_send =
                std::chrono::steady_clock::now();

        for (uint64_t sequence = 0;
             sequence < options.count;
             ++sequence)
        {
            message.sequence_number(sequence);

            // Timestamp immediately before DDS write()
            message.send_timestamp_ns(
                monotonic_time_ns());

            ReturnCode_t result =
                    writer_->write(&message);

            if (result != RETCODE_OK)
            {
                std::cerr
                    << "write() failed at sequence "
                    << sequence
                    << '\n';
            }

            if (sequence < 5 ||
                    sequence + 1 == options.count)
            {
                std::cout
                    << "SENT"
                    << " node=" << options.node_id
                    << " flow=" << options.flow_id
                    << " seq=" << sequence
                    << " payload="
                    << options.payload_bytes
                    << " B\n";
            }

            next_send +=
                    std::chrono::milliseconds(
                        options.period_ms);

            std::this_thread::sleep_until(next_send);
        }

        ReturnCode_t ack_result =
                writer_->wait_for_acknowledgments(
                eprosima::fastdds::dds::Duration_t(2, 0));

        if (ack_result != RETCODE_OK)
        {
            std::cerr
                << "Warning: timeout waiting for DDS acknowledgments.\n";
        }

        std::cout
            << "\nTransmission completed: "
            << options.count
            << " samples.\n";
    }
};

} 

int main(
        int argc,
        char** argv)
{
    Options options;

    try
    {
        if (!parse_arguments(
                argc,
                argv,
                options))
        {
            print_usage(argv[0]);
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr
            << "Invalid argument: "
            << e.what()
            << '\n';

        return 1;
    }

    CmsPublisher publisher;

    if (!publisher.init(options))
    {
        return 1;
    }

    publisher.run(options);

    return 0;
}
