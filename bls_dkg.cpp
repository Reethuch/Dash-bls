// Copyright (c) 2018-2021 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <random.h>
#include <bls/bls_worker.h>

extern CBLSWorker blsWorker;

struct Member {
    CBLSId id;

    BLSVerificationVectorPtr vvec;
    BLSSecretKeyVector skShares;
};

struct DKG
{
    std::vector<Member> members;
    std::vector<CBLSId> ids;

    std::vector<BLSVerificationVectorPtr> receivedVvecs;
    BLSSecretKeyVector receivedSkShares;

    BLSVerificationVectorPtr quorumVvec;

    DKG(int quorumSize)
    {
        members.reserve(quorumSize);
        ids.reserve(quorumSize);

        for (int i = 0; i < quorumSize; i++) {
            uint256 id;
            WriteLE64(id.begin(), i + 1);
            members.push_back({id, {}, {}});
            ids.emplace_back(id);
        }

        for (int i = 0; i < quorumSize; i++) {
	    //std::cout<<"calling Generate contributions  :: "<<i<<std::endl; //vrc
            blsWorker.GenerateContributions(quorumSize / 2 + 1, ids, members[i].vvec, members[i].skShares);
        }
	std::cout<<"Done with generating contributions"<<std::endl; //VRC
        //printf("initialized quorum %d\n", quorumSize);
    }

    void ReceiveVvecs()
    {
        receivedVvecs.clear();
        for (size_t i = 0; i < members.size(); i++) {
            receivedVvecs.emplace_back(members[i].vvec);
        }
        quorumVvec = blsWorker.BuildQuorumVerificationVector(receivedVvecs);
    }

    void ReceiveShares(size_t whoAmI)
    {
        receivedSkShares.clear();
        for (size_t i = 0; i < members.size(); i++) {
            receivedSkShares.emplace_back(members[i].skShares[whoAmI]);
        }
    }

    void BuildQuorumVerificationVector(bool parallel)
    {
        quorumVvec = blsWorker.BuildQuorumVerificationVector(receivedVvecs, 0, 0, parallel);
        //assert(worker.VerifyVerificationVector(*members[memberIdx].quorumVvec));
    }

    void Bench_BuildQuorumVerificationVectors(benchmark::State& state, bool parallel)
    {
        ReceiveVvecs();

        while (state.KeepRunning()) {
            BuildQuorumVerificationVector(parallel);
        }
    }

    void VerifyContributionShares(size_t whoAmI, const std::set<size_t>& invalidIndexes, bool parallel, bool aggregated)
    {
        auto result = blsWorker.VerifyContributionShares(members[whoAmI].id, receivedVvecs, receivedSkShares, parallel, aggregated);
        for (size_t i = 0; i < receivedVvecs.size(); i++) {
            if (invalidIndexes.count(i)) {
                assert(!result[i]);
            } else {
                assert(result[i]);
            }
        }
    }

    void Bench_VerifyContributionShares(benchmark::State& state, int invalidCount, bool parallel, bool aggregated)
    {
	std::cout<<"------afetr bench calling ReceiveVvecs()------"; //VRC
        ReceiveVvecs(); //Obtained in generated Contributions | receivedVvecs vvecs of each member is stored here  
	std::cout<<"obtained vvecs"; //VRC
        // Benchmark.
        size_t memberIdx = 0;
	std::cout<<"now we will start parsing through each memberIdx"<<'\n';
        while (state.KeepRunning()) {   // loop is running from member 0 till end
            auto& m = members[memberIdx]; 
            ReceiveShares(memberIdx); // receivedSkShares  
	    std::cout<<"Recieved secret shares for member :: "<<memberIdx<<'\n'; // std::cout<<"invalid count ->"<<invalidCount<<std::endl;
            std::set<size_t> invalidIndexes;
            for (int i = 0; i < invalidCount; i++) {
                int shareIdx = GetRandInt(receivedSkShares.size());
//vrc		std::cout<<"corrupting the skshares of this id::"<<shareIdx<<'\n';
                receivedSkShares[shareIdx].MakeNewKey(); //Assign 
                invalidIndexes.emplace(shareIdx);
            }
	    std::cout<<"verifying contribution shares"<<'\n';
            VerifyContributionShares(memberIdx, invalidIndexes, parallel, aggregated);

            memberIdx = (memberIdx + 1) % members.size();
        }
    }
};

std::shared_ptr<DKG> dkg10;
std::shared_ptr<DKG> dkg100;
//VRC std::shared_ptr<DKG> dkg400;

void InitIfNeeded()
{
    if (dkg10 == nullptr) {
        dkg10 = std::make_shared<DKG>(10);
    }
    if (dkg100 == nullptr) {
        dkg100 = std::make_shared<DKG>(100);
    }
    /*if (dkg400 == nullptr) {
        dkg400 = std::make_shared<DKG>(400);
    }*/ //VRC
}

void CleanupBLSDkgTests()
{
    dkg10.reset();
    dkg100.reset();
    //vrc dkg400.reset();
}



#define BENCH_BuildQuorumVerificationVectors(name, quorumSize, parallel, num_iters_for_one_second) \
    static void BLSDKG_BuildQuorumVerificationVectors_##name##_##quorumSize(benchmark::State& state) \
    { \
        InitIfNeeded(); \
        dkg##quorumSize->Bench_BuildQuorumVerificationVectors(state, parallel); \
    } \
    BENCHMARK(BLSDKG_BuildQuorumVerificationVectors_##name##_##quorumSize, num_iters_for_one_second)



//BENCH_BuildQuorumVerificationVectors(simple, 10, false, 1) // vrc commented11000)
//BENCH_BuildQuorumVerificationVectors(simple, 100, false, 110)
/*BENCH_BuildQuorumVerificationVectors(simple, 400, false, 6)
*/
//BENCH_BuildQuorumVerificationVectors(parallel, 10, true, 1)  //vrc commented2000)
//BENCH_BuildQuorumVerificationVectors(parallel, 100, true, 170)
// vrc BENCH_BuildQuorumVerificationVectors(parallel, 400, true, 8)



#define BENCH_VerifyContributionShares(name, quorumSize, invalidCount, parallel, aggregated, num_iters_for_one_second) \
    static void BLSDKG_VerifyContributionShares_##name##_##quorumSize(benchmark::State& state) \
    { \
        InitIfNeeded(); \
        dkg##quorumSize->Bench_VerifyContributionShares(state, invalidCount, parallel, aggregated); \
    } \
    BENCHMARK(BLSDKG_VerifyContributionShares_##name##_##quorumSize, num_iters_for_one_second)

//BENCH_VerifyContributionShares(simple, 10, 5, false, false, 7)  // name:: Simple, 10 quorumSize, invalidCount 5, parallel = false, aggregated = false, num_of_iter_per_Sec 70 , 
//BENCH_VerifyContributionShares(simple, 100, 5, false, false, 1)
//BENCH_VerifyContributionShares(simple, 400, 5, false, false, 1)

//BENCH_VerifyContributionShares(aggregated, 10, 5, false, true, 70)
//BENCH_VerifyContributionShares(aggregated, 100, 5, false, true, 2)
//BENCH_VerifyContributionShares(aggregated, 400, 5, false, true, 1)

BENCH_VerifyContributionShares(parallel, 10, 5, true, false, 200)
//BENCH_VerifyContributionShares(parallel, 100, 5, true, false, 2)
//BENCH_VerifyContributionShares(parallel, 400, 5, true, false, 1)

BENCH_VerifyContributionShares(parallel_aggregated, 10, 5, true, true, 150)

//BENCH_VerifyContributionShares(parallel_aggregated, 100, 5, true, true, 4)
//BENCH_VerifyContributionShares(parallel_aggregated, 400, 5, true, true, 1)


