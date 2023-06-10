import dataclasses

from llama_index import SimpleDirectoryReader, LLMPredictor, PromptHelper, StorageContext, ServiceContext, GPTVectorStoreIndex, load_index_from_storage
from langchain.chat_models import ChatOpenAI
import gradio as gr
import sys
import os
#
#
#
import openai
from llama_index.node_parser import SimpleNodeParser
from langchain.text_splitter import RecursiveCharacterTextSplitter

from DevSecOpsKB.my_helper import get_time

os.environ["OPENAI_API_KEY"] = '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'
# os.environ["all_proxy"] = "http://127.0.0.1:59998"
print(
    os.getenv('OPENAI_API_KEY')
)
# WARN 本来，是没有这一句的。直接全部走【环境变量】…………………………
openai.api_key = os.getenv('OPENAI_API_KEY')
openai.proxy = "http://127.0.0.1:59998"


# os.environ["OPENAI_API_BASE"] = 'https://api.chatanywhere.cn'


def simple_openai():
    # Note: you need to be using OpenAI Python v0.27.0 for the code below to work
    response = openai.ChatCompletion.create(
        # model="gpt-3.5-turbo-0301",
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Who won the world series in 2020?"},
            {"role": "assistant", "content": "The Los Angeles Dodgers won the World Series in 2020."},
            {"role": "user", "content": "Where was it played?"}
        ]
    )
    print(response)
    # print(response['choices'][0]['message']['content'])


# simple_openai()  # 测试一下，基本的OpenAI的API调用。


@dataclasses.dataclass
class _cfg:
    max_input_size: int
    num_outputs: int
    max_chunk_overlap: int
    chunk_overlap_ratio: float
    chunk_size_limit: int


def get_cfg():
    default = _cfg(
        max_input_size=4096,
        num_outputs=512,
        max_chunk_overlap=20,
        chunk_overlap_ratio=-1,
        chunk_size_limit=1000,
    )

    """
    测试情况：



    【140秒】

    请教我一些，关于【堆调试】的技巧。

    请尽可能的详细，并用中文回答。

    并对每个知识点，进行展开说明。

    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    根据新的上下文，可以看出在堆调试中，使用Windbg的!heap命令查找堆中的信息时，需要注意堆头信息和堆块数据的起始地址。在这个例子中，!heap -p -a 0x710498命令返回了堆块的详细信息，其中包括堆块的起始地址为0x00710498，大小为0x10，堆块数据的起始地址为0x007104a0。同时，还可以看到该堆块处于未释放状态，即被占用。在确定问题的根源并下断点后，需要使用Windbg的其他命令来检查堆块数据的大小和布局，并在相应的地址处进行调试。同时，也需要注意堆块数据的内容，以帮助定位问题。在调试过程中，可以使用Windbg的单步执行命令来逐步执行程序，以便更好地理解程序的执行过程。


    ——————————————————————————————————————————————————————

    【】



    """
    a_num_num_outputs = 512 * 6 - 100
    a = _cfg(
        max_input_size=4096,
        num_outputs=a_num_num_outputs,
        chunk_overlap_ratio=0.1,
        #
        max_chunk_overlap=20,
        chunk_size_limit=a_num_num_outputs,
    )

    """
    测试情况：



    【160秒】

    请教我一些，关于【堆调试】的技巧。

    请尽可能的详细，并用中文回答。

    并对每个知识点，进行展开说明。

    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>

根据提供的上下文，可以看出程序在调用00401000函数时触发了异常，这个函数是程序的主入口函数。通过栈回溯，可以定位到调用rep movs的上一层函数位于image00400000+0x1084的上一条指令，也就是00401322。

因此，可以在00401322处下断点，然后使用Windbg调试程序。当程序执行到00401322处时，就会停在断点处，此时可以使用命令u查看反汇编代码，找到调用rep movs的指令。然后可以使用命令dd查看堆栈中的数据，找到溢出的数据，进一步分析漏洞。

综上所述，通过栈回溯和反汇编代码，可以定位到调用rep movs的指令，进一步分析堆溢出漏洞。可以在00401322处下断点，使用Windbg调试程序，查看反汇编代码和堆栈数据，进一步分析漏洞。

    ——————————————————————————————————————————————————————

    【220秒】

请教我一些，关于【堆调试】的技巧。

请尽可能的详细，并用中文回答。

并对每个知识点，进行展开说明。

    >>>>>>>>>>>>>>>>>>>>>>>>>>>>>
Thank you for providing additional context. However, the provided code snippet and stack trace do not appear to be related to heap debugging or buffer overflows. The code snippet appears to be disassembled x86 assembly code, and the stack trace shows the call stack leading up to the main entry point of the program. 

Therefore, the original answer remains the same: 

To debug heap-related issues, there are several techniques and tools available. Some common techniques include:

1. Heap tracing: This involves logging all heap-related operations (such as allocations and deallocations) and analyzing the logs to identify any issues. This can be done manually or using specialized tools.

2. Heap profiling: This involves analyzing the heap usage patterns of the program to identify any inefficiencies or potential issues. This can be done using specialized profiling tools.

3. Memory debugging tools: There are several memory debugging tools available that can help identify heap-related issues, such as buffer overflows and memory leaks. Some popular tools include Valgrind, AddressSanitizer, and MemorySanitizer.

4. Code review: Reviewing the code for potential heap-related issues, such as incorrect memory management or buffer overflows, can also help identify and prevent issues.

It is important to note that debugging heap-related issues can be complex and time-consuming, and may require a combination of these techniques and tools.


    """
    b_num_num_outputs = 512 * 5 - 100
    b = _cfg(
        max_input_size=4096,
        num_outputs=b_num_num_outputs,
        chunk_overlap_ratio=0.1,
        #
        max_chunk_overlap=-1,
        chunk_size_limit=-1,
    )

    #
    #
    #

    """
    【30秒】
    
请教我一些，关于【堆调试】的技巧。

请尽可能的详细，并用中文回答。

并对每个知识点，进行展开说明。

    >>>>>>>>>>>>>>>>>>>>>

根据新的上下文，这段代码是在调用image00400000+0x1000函数之前执行的。可以看到，在00401322处，使用了call指令调用了image00400000+0x1000函数。在00401000处，可以看到该函数开辟了24h大小的栈空间，并将8赋值给ecx寄存器。因此，可以推断出该函数的作用是在栈上分配一块大小为8的内存空间。

堆调试技巧在这里可能不适用，因为这段代码并没有涉及到堆的分配和释放。如果需要进行堆调试，需要找到涉及到堆的代码段。
    
    """

    #
    #
    #

    c_num_num_outputs = 512 * 1 - 0 * 100
    c = _cfg(
        max_input_size=4096,
        num_outputs=c_num_num_outputs,
        chunk_overlap_ratio=0.1,
        #
        #
        #
        #
        #
        #
        max_chunk_overlap=---------------------1_00,
        chunk_size_limit=----------------------1_000,
    )

    #
    #
    #

    """

【这种情况，不会触发chunk长度相关。    但是，没有结果写出来】
512 * 6 - 1 * 100                                                       此时，有【多次openai的接口重试错误】
    
请为我总结，在【知识库】中，所有和【sql注入攻击】相关的信息。

要求：
① 尽可能详细
② 用中文进行表达
③ 如果有链接，请附带相关的链接进行显示。
④ 对于找到的每个知识点，除了列出重点标题信息之外，请展开详细做逐一介绍。
    
——————————————————————————————————————————————————————————————————————————————————————————
    
【这种情况，会触发chunk长度相关报错。】    （就少了，攻击  两字）
512 * 6 - 1 * 100

请为我总结，在【知识库】中，所有和【sql注入】相关的信息。

要求：
① 尽可能详细
② 用中文进行表达
③ 如果有链接，请附带相关的链接进行显示。
④ 对于找到的每个知识点，除了列出重点标题信息之外，请展开详细做逐一介绍。

    
——————————————————————————————————————————————————————————————————————————————————————————

【这种情况，会触发chunk长度相关报错。】    （就少了，攻击  两字）
512 * 5 - 1 * 100           似乎，也不会有【多次尝试的错误】？？？

请为我总结，在【知识库】中，所有和【sql注入】相关的信息。

要求：
① 尽可能详细
② 用中文进行表达
③ 如果有链接，请附带相关的链接进行显示。
④ 对于找到的每个知识点，除了列出重点标题信息之外，请展开详细做逐一介绍。

    
——————————————————————————————————————————————————————————————————————————————————————————


（就少了，攻击  两字）
————————————————【temperature】为0时
尝试了多次。有时候报【chunk overlap】错误；有时候【成功但没查到结果】。极少数时候，能够给出，相当详细的结果（大概60多秒）。
————————————————，【temperature】为0.2时
很容易，得出详细的信息。时长，大概是【70+秒】。
————————————————，【temperature】为0.3时
似乎，报错的几率就很高？？？？？？
发现，如果【关闭老版，重新启动新版】；基本上，就没有了【报错几率】……………………………………  看来，可能是【新版老版同时启动，依赖版本不一样】  所导致的。？
————————————————————————————————————————————————————
512 * 4 - 1 * 100         

请为我总结，在【知识库】中，所有和【sql注入】相关的信息。

要求：
① 尽可能详细
② 用中文进行表达
③ 如果有链接，请附带相关的链接进行显示。
④ 对于找到的每个知识点，除了列出重点标题信息之外，请展开详细做逐一介绍。  


    """
    # WARN 经过我多次发现！！！！！！    【成功但没查到结果】，只是因为【有上下文记忆】！！！！！！
    #               而【上下文记忆】，我初步发现，不是因为前端（因为前端接口，已经看过了，没有发  上一次的内容）；  那应该是哪里，出问题了呢？
    #               是否和【gradio    session_hash】    有关？？？
    #               手动，做了其中一个实验：
    #                       每次都Clear，再【发送】
    #                               后来发现，仍然有那种【有上下文记忆】所以才【成功但没查到结果】的一个表现！！！
    d_num_num_outputs = 512 * 4 - 1 * 100
    d = _cfg(
        max_input_size=4096,
        num_outputs=d_num_num_outputs,
        chunk_overlap_ratio=0.1,
        #
        #
        #
        #
        #
        #
        max_chunk_overlap=---------------------1_00,
        chunk_size_limit=----------------------1_000,
    )

    """
    采用这种方式，就查不到任何的内容了？？？？？？？？
    
    把【temperature】设置为【0.5】，试试看？
            后来发现，这种方式，也是不可以！
                    蛋疼
    
    """
    e_num_num_outputs = 512 * 1 - 0 * 100
    e = _cfg(
        max_input_size=4096,
        num_outputs=e_num_num_outputs,
        chunk_overlap_ratio=0.1,
        #
        #
        #
        #
        #
        #
        max_chunk_overlap=---------------------1_00,
        chunk_size_limit=----------------------1_000,
    )

    """
    ————————————————，【temperature】为0.2时
    测试，这个结果
    
    找不到
    
    f_num_num_outputs  为2倍
    为什么，都是找不到信息的相关提示？？？？？？
            大概，3/4的概率？？？
    找不到
    
    
    f_num_num_outputs  为3倍
    找不到
    
    f_num_num_outputs  为4倍
    
    稍微好起来了。有高效的结果了。
    
    但是，仍然会有，找不到的情况……………………
    
    """

    f_num_num_outputs = 512 * 6 - 1 * 100
    f = _cfg(
        max_input_size=4096,
        num_outputs=f_num_num_outputs,
        chunk_overlap_ratio=0.3,
        #
        #
        #
        #
        #
        #
        max_chunk_overlap=---------------------1_00,
        chunk_size_limit=----------------------1_000,
    )

    """
    将【chunk_overlap_ratio】，调为【0.3】
    
    ——————————————————————————
    
    
    
    """
    g_num_num_outputs = 512 * 4 - 1 * 100
    g = _cfg(
        max_input_size=4096,
        num_outputs=g_num_num_outputs,
        chunk_overlap_ratio=0.3,
        #
        #
        #
        #
        #
        #
        max_chunk_overlap=---------------------1_00,
        chunk_size_limit=----------------------1_000,
    )

    return g
    # _cfg(
    #     max_input_size=max_input_size,
    #     num_outputs=num_outputs,
    #     max_chunk_overlap=max_chunk_overlap,
    #     chunk_overlap_ratio=chunk_overlap_ratio,
    #     chunk_size_limit=chunk_size_limit,
    # )


def create_service_context():
    cfg = get_cfg()

    # allows the user to explicitly set certain constraint parameters
    prompt_helper = PromptHelper(
        context_window=cfg.max_input_size,  # TIP 必传
        num_output=cfg.num_outputs,  # TIP 必传
        chunk_overlap_ratio=cfg.chunk_overlap_ratio,  # TIP 必传
        #
        #
        #
        # chunk_size_limit=cfg.chunk_size_limit,  # TIP 也可以，不传。
        # max_chunk_overlap=cfg.max_chunk_overlap,  # WARN 已过时
        # max_chunk_overlap,
    )

    # LLMPredictor is a wrapper class around LangChain's LLMChain that allows easy integration into LlamaIndex
    llm_predictor = LLMPredictor(llm=ChatOpenAI(
        # temperature=0.7,
        # temperature=0.5,
        # temperature=0.3,
        temperature=0.2,
        # temperature=0.0,
        # openai_api_base="",
        #
        model_name="gpt-3.5-turbo",
        max_tokens=cfg.num_outputs,
        #
        #
        #
        # n=2,  # 试一下，这个？  消耗双倍，可能结果好一点。

    ))

    # constructs service_context
    service_context = ServiceContext.from_defaults(
        llm_predictor=llm_predictor, prompt_helper=prompt_helper,  #
        context_window=cfg.max_input_size,  # TIP 可不传
        num_output=cfg.num_outputs,  # TIP 可不传
        # TIP 增加一个，分词器      WARN 加了之后，仍然有错误
        # WARN 这段话，会极大的【增加响应时间】减慢【响应速度】！！！！！！  并且，会增加【非常多的再尝试次数！！！】！！！
        # node_parser=SimpleNodeParser(text_splitter=RecursiveCharacterTextSplitter()),
    )
    return service_context


_ctx = create_service_context()


# 读取【数据目录】
def data_ingestion_indexing(directory_path):
    # loads data from the specified directory path
    documents = SimpleDirectoryReader(directory_path).load_data()

    # when first building the index
    index = GPTVectorStoreIndex.from_documents(
        documents, service_context=_ctx
    )

    # TIP 持久化，相关。
    # persist index to disk, default "storage" folder
    index.storage_context.persist()

    return index

@get_time
def data_querying(input_text):
    # TIP 尝试，从本地存储，去读取一些东西。
    # rebuild storage context
    storage_context = StorageContext.from_defaults(persist_dir="./storage")

    # loads index from storage
    index = load_index_from_storage(storage_context, service_context=_ctx)

    print("input_text", input_text)

    # queries the index with the input text
    response = index.as_query_engine().query(input_text)

    return response.response


iface = gr.Interface(
    # 输入的回调方法
    fn=data_querying,
    # 左边框
    inputs=gr.components.Textbox(lines=7, label="Enter your question"),
    # 右边显示
    outputs="text",
    # 上面标题
    # title="Wenqi's Custom-trained DevSecOps Knowledge Base",
    title="我好想做嘉然小姐的狗啊~我好想做嘉然小姐的狗啊~我好想做嘉然小姐的狗啊~",
)

# passes in data directory
index = data_ingestion_indexing("data_cn")
iface.launch(
    # share=False,
    # share=True,  # WARN 会在【公网】进行开放
    server_name="0.0.0.0",
    server_port=18888,
)
